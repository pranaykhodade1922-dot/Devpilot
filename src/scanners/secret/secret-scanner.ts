import fs from 'node:fs';
import path from 'node:path';
import type { SecurityFinding, SeverityLevel } from '../../core/finding.js';
import type {
  SecretProgressEvent,
  SecretScanOptions,
  SecretScanResult,
  SecretScanSummary,
  SecretScanStatus,
  SecretRule
} from './types.js';
import { BUILT_IN_RULES, evaluateLineRules } from './rules.js';
import { maskSecret, redactSecretFromLine, redactPrivateKeyBlocks } from './masking.js';
import { crawlProjectFiles } from './file-crawler.js';

/**
 * Maps a secret match to a unified SecurityFinding object.
 *
 * CRITICAL INVARIANT:
 * Raw secret values are NEVER stored in evidence, description, title, or any finding property.
 */
export function createSecretFinding(params: {
  rule: SecretRule;
  filePath: string;
  relPath: string;
  lineNumber: number;
  columnNumber: number;
  redactedLine: string;
  maskedSecret: string;
}): SecurityFinding {
  const { rule, relPath, lineNumber, columnNumber, redactedLine, maskedSecret } = params;

  return {
    id: `${rule.id}-${relPath}:${lineNumber}:${columnNumber}`,
    scanner: 'secret-scanner',
    packageName: relPath,
    installedVersion: `L${lineNumber}:C${columnNumber}`,
    vulnerabilityId: rule.id,
    aliases: [rule.category],
    title: `${rule.name} detected in ${relPath}`,
    description: `A potential secret of type '${rule.name}' was detected at line ${lineNumber}, column ${columnNumber} in file '${relPath}'.`,
    severity: rule.severity,
    severitySource: 'explicit_score',
    fixedVersions: [],
    references: [],
    dependencyType: 'direct',
    confidence: rule.confidence,
    evidence: redactedLine.trim(),
    remediation: rule.remediation,
    remediationDetails: {
      notes: `Secret value masked: ${maskedSecret}`
    }
  };
}

/**
 * Scans an individual text file for secrets line by line.
 */
export async function scanFileForSecrets(
  filePath: string,
  rootDir: string,
  rules: SecretRule[] = BUILT_IN_RULES
): Promise<{ findings: SecurityFinding[]; lineCount: number }> {
  const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
  let rawContent: string;

  try {
    rawContent = await fs.promises.readFile(filePath, 'utf8');
  } catch {
    return { findings: [], lineCount: 0 };
  }

  // Pre-process multiline private-key blocks so body bytes cannot appear in any line evidence
  const sanitizedContent = redactPrivateKeyBlocks(rawContent);
  const lines = sanitizedContent.split(/\r?\n/);
  const findings: SecurityFinding[] = [];

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNumber = idx + 1;
    const lineContent = lines[idx] ?? '';

    if (!lineContent || lineContent.trim().length === 0) {
      continue;
    }

    const matches = evaluateLineRules(lineContent, lineNumber, relPath, rules, lines);

    for (const match of matches) {
      const rawSecret = lineContent.slice(match.startOffset, match.endOffset);
      const maskedSecret = maskSecret(rawSecret);
      const redactedLine = redactSecretFromLine(
        lineContent,
        rawSecret,
        match.startOffset,
        match.endOffset
      );

      const finding = createSecretFinding({
        rule: match.rule,
        filePath,
        relPath,
        lineNumber,
        columnNumber: match.startOffset + 1,
        redactedLine,
        maskedSecret
      });

      findings.push(finding);
    }
  }

  return { findings, lineCount: lines.length };
}

/**
 * Determines overall scan status using standardized CLI exit-code conventions:
 * - CLEAN (0): Complete scan, zero findings, zero error-skipped files.
 * - VULNERABLE (1): Findings detected, zero error-skipped files.
 * - PARTIAL (3): Some eligible files could not be scanned due to I/O/permission/binary errors.
 * - FAILED (2): Target directory not found or unrecoverable error.
 */
export function computeSecretScanStatus(
  findingsCount: number,
  errorSkippedCount: number
): SecretScanStatus {
  if (errorSkippedCount > 0) {
    return 'PARTIAL'; // Exit Code 3
  }
  if (findingsCount > 0) {
    return 'VULNERABLE'; // Exit Code 1
  }
  return 'CLEAN'; // Exit Code 0
}

/**
 * Safely emits a secret scanner progress event.
 * Exceptions inside consumer callbacks are caught and swallowed to guarantee
 * scanner stability and accurate exit code execution.
 */
function safeEmitProgress(
  onProgress: ((event: SecretProgressEvent) => void) | undefined,
  event: SecretProgressEvent
): void {
  if (!onProgress) return;
  try {
    onProgress(event);
  } catch {
    // Isolated: callback failure must never disrupt scanner or alter findings
  }
}

/**
 * Main orchestrator for secret scanning across a project directory.
 */
export async function scanSecrets(
  options: SecretScanOptions = {}
): Promise<SecretScanResult> {
  const startTime = Date.now();
  const rootDir = path.resolve(options.cwd ?? process.cwd());
  const rules = options.customRules ?? BUILT_IN_RULES;

  safeEmitProgress(options.onProgress, {
    stage: 'discovery',
    status: 'started',
    message: 'Discovering project files...'
  });

  // 1. Crawl eligible files
  const crawl = await crawlProjectFiles({
    rootDir,
    maxFileSize: options.maxFileSize,
    respectGitignore: options.respectGitignore
  });

  // Handle fatal crawl failure (e.g., root directory does not exist)
  if (
    crawl.eligibleFiles.length === 0 &&
    crawl.errorSkipped.length > 0 &&
    crawl.errorSkipped.some((s) => s.filePath === rootDir)
  ) {
    const errorRecord = crawl.errorSkipped.find((s) => s.filePath === rootDir);
    const durationMs = Date.now() - startTime;
    const errMsg = errorRecord?.details ?? 'Target path could not be accessed';

    safeEmitProgress(options.onProgress, {
      stage: 'discovery',
      status: 'failed',
      message: errMsg,
      metadata: {
        errorMessage: errMsg,
        errorSkippedCount: crawl.errorSkipped.length,
        durationMs
      }
    });

    safeEmitProgress(options.onProgress, {
      stage: 'completed',
      status: 'failed',
      message: 'Secret scan failed during file discovery',
      metadata: {
        errorMessage: errMsg,
        errorSkippedCount: crawl.errorSkipped.length,
        durationMs
      }
    });

    return {
      summary: {
        totalFilesScanned: 0,
        totalLinesScanned: 0,
        findingsCount: 0,
        severityCounts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
        scanStatus: 'FAILED',
        skippedFiles: crawl.errorSkipped,
        errorSkippedCount: crawl.errorSkipped.length,
        intentionalSkippedCount: 0,
        durationMs,
        errorMessage: errMsg
      },
      findings: []
    };
  }

  safeEmitProgress(options.onProgress, {
    stage: 'discovery',
    status: 'completed',
    completed: crawl.eligibleFiles.length,
    total: crawl.eligibleFiles.length,
    message: `Discovered ${crawl.eligibleFiles.length} eligible files`,
    metadata: {
      eligibleFilesCount: crawl.eligibleFiles.length,
      errorSkippedCount: crawl.errorSkipped.length,
      intentionalSkippedCount: crawl.intentionallyExcluded.length
    }
  });

  // 2. Scan eligible text files
  const allFindings: SecurityFinding[] = [];
  let totalLinesScanned = 0;

  if (crawl.eligibleFiles.length === 0) {
    const allSkipped = [...crawl.intentionallyExcluded, ...crawl.errorSkipped];
    const durationMs = Date.now() - startTime;
    const scanStatus = computeSecretScanStatus(0, crawl.errorSkipped.length);

    safeEmitProgress(options.onProgress, {
      stage: 'completed',
      status: scanStatus === 'PARTIAL' ? 'partial' : 'completed',
      outcome: scanStatus === 'PARTIAL' ? undefined : 'clean',
      message: 'No eligible files found to scan',
      metadata: {
        eligibleFilesCount: 0,
        processedFilesCount: 0,
        linesExamined: 0,
        findingsCount: 0,
        errorSkippedCount: crawl.errorSkipped.length,
        intentionalSkippedCount: crawl.intentionallyExcluded.length,
        durationMs
      }
    });

    return {
      summary: {
        totalFilesScanned: 0,
        totalLinesScanned: 0,
        findingsCount: 0,
        severityCounts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
        scanStatus,
        skippedFiles: allSkipped,
        errorSkippedCount: crawl.errorSkipped.length,
        intentionalSkippedCount: crawl.intentionallyExcluded.length,
        durationMs
      },
      findings: []
    };
  }

  safeEmitProgress(options.onProgress, {
    stage: 'scanning',
    status: 'started',
    total: crawl.eligibleFiles.length,
    message: `Scanning ${crawl.eligibleFiles.length} files for secrets...`,
    metadata: {
      eligibleFilesCount: crawl.eligibleFiles.length
    }
  });

  for (let idx = 0; idx < crawl.eligibleFiles.length; idx++) {
    const file = crawl.eligibleFiles[idx]!;
    const relFile = path.relative(rootDir, file).replace(/\\/g, '/');
    const { findings, lineCount } = await scanFileForSecrets(file, rootDir, rules);
    allFindings.push(...findings);
    totalLinesScanned += lineCount;

    safeEmitProgress(options.onProgress, {
      stage: 'scanning',
      status: 'progress',
      completed: idx + 1,
      total: crawl.eligibleFiles.length,
      message: `Scanning: ${relFile}`,
      metadata: {
        currentFile: relFile,
        eligibleFilesCount: crawl.eligibleFiles.length,
        processedFilesCount: idx + 1,
        linesExamined: totalLinesScanned,
        findingsCount: allFindings.length
      }
    });
  }

  safeEmitProgress(options.onProgress, {
    stage: 'scanning',
    status: 'completed',
    completed: crawl.eligibleFiles.length,
    total: crawl.eligibleFiles.length,
    message: `Scanned ${crawl.eligibleFiles.length} files (${totalLinesScanned} lines)`
  });

  // 3. Compute severity breakdowns
  const severityCounts: Record<SeverityLevel, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MODERATE: 0,
    LOW: 0,
    UNKNOWN: 0
  };

  for (const f of allFindings) {
    severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
  }

  const allSkipped = [...crawl.intentionallyExcluded, ...crawl.errorSkipped];
  const scanStatus = computeSecretScanStatus(allFindings.length, crawl.errorSkipped.length);
  const durationMs = Date.now() - startTime;

  const summary: SecretScanSummary = {
    totalFilesScanned: crawl.eligibleFiles.length,
    totalLinesScanned,
    findingsCount: allFindings.length,
    severityCounts,
    scanStatus,
    skippedFiles: allSkipped,
    errorSkippedCount: crawl.errorSkipped.length,
    intentionalSkippedCount: crawl.intentionallyExcluded.length,
    durationMs
  };

  const terminalLifecycleStatus: 'completed' | 'partial' =
    scanStatus === 'PARTIAL' ? 'partial' : 'completed';

  const terminalOutcome: 'clean' | 'vulnerable' | undefined =
    allFindings.length > 0
      ? 'vulnerable'
      : scanStatus === 'PARTIAL'
        ? undefined
        : 'clean';

  safeEmitProgress(options.onProgress, {
    stage: 'completed',
    status: terminalLifecycleStatus,
    outcome: terminalOutcome,
    message: `Secret scan completed with status: ${scanStatus}`,
    metadata: {
      eligibleFilesCount: crawl.eligibleFiles.length,
      processedFilesCount: crawl.eligibleFiles.length,
      linesExamined: totalLinesScanned,
      findingsCount: allFindings.length,
      errorSkippedCount: crawl.errorSkipped.length,
      intentionalSkippedCount: crawl.intentionallyExcluded.length,
      durationMs
    }
  });

  return {
    summary,
    findings: allFindings
  };
}

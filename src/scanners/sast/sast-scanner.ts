import fs from 'node:fs';
import path from 'node:path';
import type { SecurityFinding, SeverityLevel } from '../../core/finding.js';
import type {
  SastProgressEvent,
  SastScanOptions,
  SastScanResult,
  SastScanSummary,
  SastScanStatus
} from './types.js';
import { crawlProjectFiles } from '../secret/file-crawler.js';
import { parseSourceCode } from './parser.js';
import { analyzeSourceFile } from './analyzer.js';
import { BUILT_IN_SAST_RULES } from './rules/index.js';
import type { SkippedFileRecord } from '../secret/types.js';

export const SAST_TARGET_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs'
]);

/**
 * Computes overall SAST scan status using CLI exit-code conventions:
 * - CLEAN (0): Scan completed successfully with zero findings and zero syntax/parse errors.
 * - VULNERABLE (1): Findings detected.
 * - PARTIAL (3): Some files had recoverable syntax errors or could not be fully parsed.
 * - FAILED (2): Target directory not found or unrecoverable error.
 */
export function computeSastScanStatus(
  findingsCount: number,
  hasSyntaxErrors: boolean,
  errorSkippedCount: number
): SastScanStatus {
  if (errorSkippedCount > 0 && findingsCount === 0) {
    return 'PARTIAL'; // Exit Code 3
  }
  if (findingsCount > 0) {
    return 'VULNERABLE'; // Exit Code 1
  }
  if (hasSyntaxErrors) {
    return 'PARTIAL'; // Exit Code 3: Never report CLEAN if syntax errors occurred
  }
  return 'CLEAN'; // Exit Code 0
}

/**
 * Safely emits a SAST scanner progress event.
 * Exceptions inside consumer callbacks are caught and swallowed to guarantee
 * scanner stability and accurate exit code execution.
 */
function safeEmitProgress(
  onProgress: ((event: SastProgressEvent) => void) | undefined,
  event: SastProgressEvent
): void {
  if (!onProgress) return;
  try {
    onProgress(event);
  } catch {
    // Isolated: callback failure must never disrupt scanner or alter findings
  }
}

/**
 * Executes static application security testing across a target project.
 */
export async function scanSast(options: SastScanOptions = {}): Promise<SastScanResult> {
  const startTime = Date.now();
  const rootDir = path.resolve(options.cwd ?? process.cwd());
  const rules = options.customRules ?? BUILT_IN_SAST_RULES;

  safeEmitProgress(options.onProgress, {
    stage: 'discovery',
    status: 'started',
    message: 'Discovering source files for SAST analysis...'
  });

  // 1. Crawl eligible files
  const crawl = await crawlProjectFiles({
    rootDir,
    maxFileSize: options.maxFileSize,
    respectGitignore: options.respectGitignore
  });

  // Handle fatal crawl failure
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
      message: 'SAST scan failed during file discovery',
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
        durationMs
      },
      findings: []
    };
  }

  // Filter crawl results down to supported JavaScript/TypeScript source files
  const sastFiles = crawl.eligibleFiles.filter((filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return SAST_TARGET_EXTENSIONS.has(ext);
  });

  safeEmitProgress(options.onProgress, {
    stage: 'discovery',
    status: 'completed',
    completed: sastFiles.length,
    total: sastFiles.length,
    message: `Discovered ${sastFiles.length} JavaScript/TypeScript source files (${crawl.eligibleFiles.length} eligible project files)`,
    metadata: {
      eligibleFilesCount: crawl.eligibleFiles.length,
      sastFilesCount: sastFiles.length,
      errorSkippedCount: crawl.errorSkipped.length,
      intentionalSkippedCount: crawl.intentionallyExcluded.length
    }
  });

  if (sastFiles.length === 0) {
    const skippedFiles: SkippedFileRecord[] = [...crawl.intentionallyExcluded, ...crawl.errorSkipped];
    const errorSkippedCount = skippedFiles.filter((s) => !s.isIntentionallyExcluded).length;
    const intentionalSkippedCount = skippedFiles.filter((s) => s.isIntentionallyExcluded).length;
    const durationMs = Date.now() - startTime;
    const scanStatus = computeSastScanStatus(0, false, errorSkippedCount);

    safeEmitProgress(options.onProgress, {
      stage: 'completed',
      status: scanStatus === 'PARTIAL' ? 'partial' : 'completed',
      outcome: scanStatus === 'PARTIAL' ? undefined : 'clean',
      message: 'No JavaScript/TypeScript source files found to scan',
      metadata: {
        eligibleFilesCount: crawl.eligibleFiles.length,
        sastFilesCount: 0,
        processedFilesCount: 0,
        linesExamined: 0,
        findingsCount: 0,
        errorSkippedCount,
        intentionalSkippedCount,
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
        skippedFiles,
        errorSkippedCount,
        intentionalSkippedCount,
        hasSyntaxErrors: false,
        durationMs
      },
      findings: []
    };
  }

  safeEmitProgress(options.onProgress, {
    stage: 'analyzing',
    status: 'started',
    total: sastFiles.length,
    message: `Analyzing ${sastFiles.length} AST source trees...`,
    metadata: {
      sastFilesCount: sastFiles.length
    }
  });

  const allFindings: SecurityFinding[] = [];
  const skippedFiles: SkippedFileRecord[] = [...crawl.intentionallyExcluded, ...crawl.errorSkipped];
  let totalLines = 0;
  let hasSyntaxErrors = false;

  for (let idx = 0; idx < sastFiles.length; idx++) {
    const filePath = sastFiles[idx]!;
    const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
    let content: string;

    try {
      content = await fs.promises.readFile(filePath, 'utf8');
    } catch (err: any) {
      skippedFiles.push({
        filePath: relPath,
        reason: 'READ_ERROR',
        isIntentionallyExcluded: false,
        details: err?.message ?? 'I/O failure reading source file'
      });
      continue;
    }

    const lines = content.split(/\r?\n/);
    totalLines += lines.length;

    // Parse source into AST
    const parseResult = parseSourceCode(filePath, content);

    if (parseResult.hasErrors) {
      hasSyntaxErrors = true;
      skippedFiles.push({
        filePath: relPath,
        reason: 'PARTIAL_ANALYSIS',
        isIntentionallyExcluded: false,
        details: `Recoverable syntax diagnostics: ${parseResult.diagnostics.slice(0, 3).join('; ')}`
      });
    }

    // Analyze AST for findings (even on partial AST recovery)
    const fileFindings = analyzeSourceFile({
      filePath,
      relPath,
      sourceFile: parseResult.sourceFile,
      rules
    });

    allFindings.push(...fileFindings);

    safeEmitProgress(options.onProgress, {
      stage: 'analyzing',
      status: 'progress',
      completed: idx + 1,
      total: sastFiles.length,
      message: `Analyzing: ${relPath}`,
      metadata: {
        currentFile: relPath,
        sastFilesCount: sastFiles.length,
        processedFilesCount: idx + 1,
        linesExamined: totalLines,
        hasSyntaxErrors: parseResult.hasErrors,
        findingsCount: allFindings.length
      }
    });
  }

  safeEmitProgress(options.onProgress, {
    stage: 'analyzing',
    status: 'completed',
    completed: sastFiles.length,
    total: sastFiles.length,
    message: `Analyzed ${sastFiles.length} files (${totalLines} lines)`
  });

  const severityCounts: Record<SeverityLevel, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MODERATE: 0,
    LOW: 0,
    UNKNOWN: 0
  };

  for (const finding of allFindings) {
    severityCounts[finding.severity]++;
  }

  const errorSkippedCount = skippedFiles.filter((s) => !s.isIntentionallyExcluded).length;
  const intentionalSkippedCount = skippedFiles.filter((s) => s.isIntentionallyExcluded).length;

  const scanStatus = computeSastScanStatus(
    allFindings.length,
    hasSyntaxErrors,
    errorSkippedCount
  );

  const durationMs = Date.now() - startTime;

  const summary: SastScanSummary = {
    totalFilesScanned: sastFiles.length,
    totalLinesScanned: totalLines,
    findingsCount: allFindings.length,
    severityCounts,
    scanStatus,
    skippedFiles,
    errorSkippedCount,
    intentionalSkippedCount,
    hasSyntaxErrors,
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
    message: `SAST scan completed with status: ${scanStatus}`,
    metadata: {
      sastFilesCount: sastFiles.length,
      processedFilesCount: sastFiles.length,
      linesExamined: totalLines,
      hasSyntaxErrors,
      findingsCount: allFindings.length,
      errorSkippedCount,
      intentionalSkippedCount,
      durationMs
    }
  });

  return {
    summary,
    findings: allFindings
  };
}

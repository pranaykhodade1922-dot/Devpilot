import path from 'node:path';
import chalk from 'chalk';
import { detectProject } from '../../core/project-detector.js';
import type { SecurityFinding, SeverityLevel } from '../../core/finding.js';
import { SEVERITY_ORDER } from '../../core/finding.js';
import { scanDependencies } from '../../scanners/dependency/dependency-scanner.js';
import type { DependencyScanResult } from '../../scanners/dependency/types.js';
import { scanSecrets } from '../../scanners/secret/secret-scanner.js';
import type { SecretScanResult } from '../../scanners/secret/types.js';
import { scanSast } from '../../scanners/sast/sast-scanner.js';
import type { SastScanResult } from '../../scanners/sast/types.js';
import {
  formatSeverityBadge,
  CLI_EXIT_CODES,
  type CliExitCode
} from './security.js';

export type ScannerExecutionStatus =
  | 'COMPLETED'
  | 'SKIPPED'
  | 'PARTIAL'
  | 'FAILED';

export interface ScannerStatusSummary {
  name: 'Dependency Scanner' | 'Secret Scanner' | 'SAST Scanner';
  status: ScannerExecutionStatus;
  findingsCount: number;
  message?: string;
  durationMs: number;
}

export interface UnifiedScanSummary {
  projectName: string;
  projectRoot: string;
  framework: string;
  language: string;
  packageManager: string;
  totalFindings: number;
  severityCounts: Record<SeverityLevel, number>;
  scanStatus: 'CLEAN' | 'VULNERABLE' | 'PARTIAL' | 'FAILED';
  durationMs: number;
  scanners: {
    dependency: ScannerStatusSummary;
    secret: ScannerStatusSummary;
    sast: ScannerStatusSummary;
  };
}

export interface UnifiedScanResult {
  summary: UnifiedScanSummary;
  findings: SecurityFinding[];
  dependencyScan?: DependencyScanResult;
  secretScan?: SecretScanResult;
  sastScan?: SastScanResult;
}

export interface ScanCommandOptions {
  json?: boolean;
}

/**
 * Deterministically determines the unified exit code and scan status.
 *
 * Rules:
 * 1. If ANY executed scanner failed fatally -> FAILED (Exit Code 2).
 * 2. Else if ANY executed scanner was partial -> PARTIAL (Exit Code 3).
 * 3. Else if any findings were detected -> VULNERABLE (Exit Code 1).
 * 4. Else -> CLEAN (Exit Code 0).
 *
 * Invariant: A fatal failure is never hidden by findings from another scanner.
 * Invariant: Never report CLEAN if any required scanner failed or was partial.
 */
export function determineUnifiedExitCode(
  depStatus: ScannerExecutionStatus,
  secStatus: ScannerExecutionStatus,
  sastStatusOrFindingsCount: ScannerExecutionStatus | number,
  findingsCountArg?: number
): { scanStatus: 'CLEAN' | 'VULNERABLE' | 'PARTIAL' | 'FAILED'; exitCode: CliExitCode } {
  let sastStatus: ScannerExecutionStatus = 'COMPLETED';
  let findingsCount = 0;

  if (typeof sastStatusOrFindingsCount === 'number') {
    findingsCount = sastStatusOrFindingsCount;
    sastStatus = 'COMPLETED';
  } else {
    sastStatus = sastStatusOrFindingsCount;
    findingsCount = findingsCountArg ?? 0;
  }

  if (depStatus === 'FAILED' || secStatus === 'FAILED' || sastStatus === 'FAILED') {
    return { scanStatus: 'FAILED', exitCode: CLI_EXIT_CODES.FAILED }; // 2
  }
  if (depStatus === 'PARTIAL' || secStatus === 'PARTIAL' || sastStatus === 'PARTIAL') {
    return { scanStatus: 'PARTIAL', exitCode: CLI_EXIT_CODES.PARTIAL }; // 3
  }
  if (findingsCount > 0) {
    return { scanStatus: 'VULNERABLE', exitCode: CLI_EXIT_CODES.VULNERABLE }; // 1
  }
  return { scanStatus: 'CLEAN', exitCode: CLI_EXIT_CODES.CLEAN }; // 0
}

/**
 * Primary unified security scanning command for DevPilot.
 *
 * Executes project inspection, dependency vulnerability scanning (OSV),
 * and local-first secret scanning across the project.
 */
export async function runScan(
  targetPath?: string,
  options: ScanCommandOptions = {}
): Promise<UnifiedScanResult> {
  const startTime = Date.now();
  const targetDir = path.resolve(targetPath ?? process.cwd());

  // 1. Detect project metadata
  const project = detectProject({ cwd: targetDir });

  // 2. Run Dependency Scanner (if applicable)
  let depResult: DependencyScanResult | undefined;
  let depStatus: ScannerExecutionStatus = 'COMPLETED';
  let depMessage: string | undefined;
  const depStart = Date.now();

  if (!project.packageJsonExists) {
    depStatus = 'SKIPPED';
    depMessage = 'No package.json detected in project';
  } else {
    try {
      depResult = await scanDependencies({ cwd: targetDir });
      if (depResult.summary.scanStatus === 'FAILED') {
        depStatus = 'FAILED';
        depMessage = depResult.summary.errorMessage ?? 'Dependency scan failed';
      } else if (depResult.summary.scanStatus === 'PARTIAL') {
        depStatus = 'PARTIAL';
        depMessage = 'Upstream advisory hydration was incomplete';
      } else {
        depStatus = 'COMPLETED';
      }
    } catch (err) {
      depStatus = 'FAILED';
      depMessage = err instanceof Error ? err.message : String(err);
    }
  }
  const depDurationMs = Date.now() - depStart;

  // 3. Run Secret Scanner
  let secResult: SecretScanResult | undefined;
  let secStatus: ScannerExecutionStatus = 'COMPLETED';
  let secMessage: string | undefined;
  const secStart = Date.now();

  try {
    secResult = await scanSecrets({ cwd: targetDir });
    if (secResult.summary.scanStatus === 'FAILED') {
      secStatus = 'FAILED';
      secMessage = secResult.summary.errorMessage ?? 'Secret scan failed';
    } else if (secResult.summary.scanStatus === 'PARTIAL') {
      secStatus = 'PARTIAL';
      secMessage = `${secResult.summary.errorSkippedCount} file(s) unreadable or exceeded size limit`;
    } else {
      secStatus = 'COMPLETED';
    }
  } catch (err) {
    secStatus = 'FAILED';
    secMessage = err instanceof Error ? err.message : String(err);
  }
  const secDurationMs = Date.now() - secStart;

  // 4. Run SAST Scanner
  let sastResult: SastScanResult | undefined;
  let sastStatus: ScannerExecutionStatus = 'COMPLETED';
  let sastMessage: string | undefined;
  const sastStart = Date.now();

  try {
    sastResult = await scanSast({ cwd: targetDir });
    if (sastResult.summary.scanStatus === 'FAILED') {
      sastStatus = 'FAILED';
      sastMessage = 'SAST scanner failed to analyze source files';
    } else if (sastResult.summary.scanStatus === 'PARTIAL') {
      sastStatus = 'PARTIAL';
      sastMessage = `${sastResult.summary.errorSkippedCount} file(s) had syntax or parse errors`;
    } else {
      sastStatus = 'COMPLETED';
    }
  } catch (err) {
    sastStatus = 'FAILED';
    sastMessage = err instanceof Error ? err.message : String(err);
  }
  const sastDurationMs = Date.now() - sastStart;

  // 5. Combine and sort findings across all active scanners
  const depFindings = depResult?.findings ?? [];
  const secFindings = secResult?.findings ?? [];
  const sastFindings = sastResult?.findings ?? [];
  const allFindings: SecurityFinding[] = [...depFindings, ...secFindings, ...sastFindings];

  allFindings.sort((a, b) => {
    const orderA = SEVERITY_ORDER[a.severity] ?? 99;
    const orderB = SEVERITY_ORDER[b.severity] ?? 99;
    return orderA - orderB;
  });

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

  // 6. Compute overall scan status and exit code
  const { scanStatus, exitCode } = determineUnifiedExitCode(
    depStatus,
    secStatus,
    sastStatus,
    allFindings.length
  );

  const durationMs = Date.now() - startTime;

  const summary: UnifiedScanSummary = {
    projectName: project.projectName,
    projectRoot: project.projectRoot,
    framework: project.framework,
    language: project.language,
    packageManager: project.packageManager,
    totalFindings: allFindings.length,
    severityCounts,
    scanStatus,
    durationMs,
    scanners: {
      dependency: {
        name: 'Dependency Scanner',
        status: depStatus,
        findingsCount: depFindings.length,
        message: depMessage,
        durationMs: depDurationMs
      },
      secret: {
        name: 'Secret Scanner',
        status: secStatus,
        findingsCount: secFindings.length,
        message: secMessage,
        durationMs: secDurationMs
      },
      sast: {
        name: 'SAST Scanner',
        status: sastStatus,
        findingsCount: sastFindings.length,
        message: sastMessage,
        durationMs: sastDurationMs
      }
    }
  };

  const unifiedResult: UnifiedScanResult = {
    summary,
    findings: allFindings,
    dependencyScan: depResult,
    secretScan: secResult,
    sastScan: sastResult
  };

  // 7. JSON output mode
  if (options.json) {
    console.log(JSON.stringify(unifiedResult, null, 2));
    process.exitCode = exitCode;
    return unifiedResult;
  }

  // 8. Human-readable combined report
  console.log();
  console.log(chalk.bold.cyan(' DevPilot Security Report'));
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(`${chalk.bold('Project:')}              ${chalk.white(summary.projectName)}`);
  console.log(`${chalk.bold('Project Root:')}         ${chalk.white(summary.projectRoot)}`);
  console.log(
    `${chalk.bold('Language / Tech:')}    ${chalk.white(summary.language)}${
      summary.framework !== 'None detected' ? chalk.gray(` (${summary.framework})`) : ''
    }`
  );
  if (summary.packageManager !== 'None detected') {
    console.log(`${chalk.bold('Package Manager:')}     ${chalk.white(summary.packageManager)}`);
  }
  console.log(
    `${chalk.bold('Scan Duration:')}        ${chalk.white(`${summary.durationMs}ms`)}`
  );
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(chalk.bold('Scanner Status:'));

  const formatStatus = (s: ScannerExecutionStatus, msg?: string) => {
    switch (s) {
      case 'COMPLETED':
        return chalk.green.bold('Completed');
      case 'SKIPPED':
        return chalk.gray(`Skipped (${msg ?? 'Not applicable'})`);
      case 'PARTIAL':
        return chalk.yellow.bold(`Partial (${msg ?? 'Incomplete data'})`);
      case 'FAILED':
        return chalk.red.bold(`Failed (${msg ?? 'Error occurred'})`);
    }
  };

  console.log(`  ${chalk.bold('Dependency Scanner:')} ${formatStatus(depStatus, depMessage)}`);
  console.log(`  ${chalk.bold('Secret Scanner:')}     ${formatStatus(secStatus, secMessage)}`);
  console.log(`  ${chalk.bold('SAST Scanner:')}       ${formatStatus(sastStatus, sastMessage)}`);
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));

  // Failure state (Exit Code 2)
  if (scanStatus === 'FAILED') {
    console.log(
      chalk.red.bold('✖ Scan Failed (Exit Code 2):') +
        ' ' +
        chalk.red('One or more security scanners failed to complete reliably.')
    );
    if (depStatus === 'FAILED' && depMessage) {
      console.log(chalk.red(`   - Dependency Scanner: ${depMessage}`));
    }
    if (secStatus === 'FAILED' && secMessage) {
      console.log(chalk.red(`   - Secret Scanner: ${secMessage}`));
    }
    if (sastStatus === 'FAILED' && sastMessage) {
      console.log(chalk.red(`   - SAST Scanner: ${sastMessage}`));
    }
    console.log(
      chalk.yellow('⚠ Caution: This scan could not be completed and must NOT be considered clean.')
    );
  } else if (scanStatus === 'PARTIAL') {
    console.log(
      chalk.yellow.bold('⚠ Scan Partially Completed (Exit Code 3):') +
        ' ' +
        chalk.yellow('One or more scanners encountered incomplete data or unreadable files.')
    );
    if (depStatus === 'PARTIAL' && depMessage) {
      console.log(chalk.yellow(`   - Dependency Scanner: ${depMessage}`));
    }
    if (secStatus === 'PARTIAL' && secMessage) {
      console.log(chalk.yellow(`   - Secret Scanner: ${secMessage}`));
    }
    if (sastStatus === 'PARTIAL' && sastMessage) {
      console.log(chalk.yellow(`   - SAST Scanner: ${sastMessage}`));
    }
    console.log(
      chalk.yellow('⚠ Caution: Due to partial scan coverage, this project cannot be certified clean.')
    );
  } else if (scanStatus === 'CLEAN') {
    console.log(
      chalk.green.bold('✔ No Security Findings Detected (Exit Code 0)') +
        chalk.gray(' across all active security scanners.')
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log();
    process.exitCode = exitCode;
    return unifiedResult;
  }

  // Display findings breakdown and detailed list
  if (allFindings.length > 0) {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(`${chalk.bold('Total findings:')}        ${chalk.red.bold(String(summary.totalFindings))}`);
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(chalk.bold('Findings by Severity:'));
    console.log(
      `  ${formatSeverityBadge('CRITICAL')} ${chalk.bold(String(summary.severityCounts.CRITICAL))}  ` +
        `  ${formatSeverityBadge('HIGH')} ${chalk.bold(String(summary.severityCounts.HIGH))}  ` +
        `  ${formatSeverityBadge('MODERATE')} ${chalk.bold(String(summary.severityCounts.MODERATE))}  ` +
        `  ${formatSeverityBadge('LOW')} ${chalk.bold(String(summary.severityCounts.LOW))}  ` +
        `  ${formatSeverityBadge('UNKNOWN')} ${chalk.bold(String(summary.severityCounts.UNKNOWN))}`
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(chalk.bold('Findings Details:'));
    console.log();

    allFindings.forEach((finding, idx) => {
      const badge = formatSeverityBadge(finding.severity);
      let scannerLabel: string;
      if (finding.scanner === 'secret-scanner') {
        scannerLabel = chalk.bgHex('#7B1FA2').white.bold(' SECRET ');
      } else if (finding.scanner === 'sast-scanner') {
        scannerLabel = chalk.bgHex('#D84315').white.bold(' SAST ');
      } else {
        scannerLabel = chalk.bgHex('#1565C0').white.bold(' DEPENDENCY ');
      }

      const location = chalk.white.bold(
        finding.location
          ? `${finding.location.filePath}:${finding.location.line}:${finding.location.column}`
          : `${finding.packageName} ${finding.installedVersion}`
      );

      console.log(`${chalk.bold(`${idx + 1}.`)} ${badge} ${scannerLabel} ${location}`);
      console.log(`   ${chalk.bold('Issue:')}        ${chalk.cyan(finding.vulnerabilityId)} — ${finding.title}`);
      console.log(`   ${chalk.bold('Evidence:')}     ${chalk.gray(finding.evidence)}`);
      if (finding.remediationDetails?.notes) {
        console.log(`   ${chalk.bold('Notes:')}        ${chalk.yellow(finding.remediationDetails.notes)}`);
      }
      console.log(`   ${chalk.bold('Remediation:')}  ${chalk.green(finding.remediation)}`);
      if (finding.references && finding.references.length > 0) {
        console.log(`   ${chalk.bold('Reference:')}    ${chalk.blue.underline(finding.references[0])}`);
      }
      console.log();
    });
  } else {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(chalk.yellow('No findings were identified in the completed portions of the scan.'));
  }

  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    chalk.yellow.bold('ℹ Remediation Guidance:') +
      chalk.white(
        ' Prioritize CRITICAL and HIGH severities. Revoke any exposed secrets immediately, upgrade vulnerable dependencies, and remediate risky source-code patterns before deploying.'
      )
  );
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log();

  process.exitCode = exitCode;
  return unifiedResult;
}

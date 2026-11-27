import path from 'node:path';
import chalk from 'chalk';
import type { SeverityLevel } from '../../core/finding.js';
import { scanDependencies } from '../../scanners/dependency/dependency-scanner.js';
import type { DependencyScanResult, DependencyScanSummary } from '../../scanners/dependency/types.js';
import { scanSecrets } from '../../scanners/secret/secret-scanner.js';
import type {
  SecretScanResult,
  SecretScanSummary
} from '../../scanners/secret/types.js';
import { scanSast } from '../../scanners/sast/sast-scanner.js';
import type { SastScanResult, SastScanSummary } from '../../scanners/sast/types.js';

export interface SecurityDepsCommandOptions {
  json?: boolean;
}

export interface SecuritySecretsCommandOptions {
  json?: boolean;
}

export interface SecuritySastCommandOptions {
  json?: boolean;
}

/**
 * Predictable exit codes for DevPilot Security:
 * - 0: Scan completed successfully with no vulnerabilities found.
 * - 1: Scan completed successfully and one or more vulnerabilities were found.
 * - 2: Scan failed or could not complete reliably (e.g., missing lockfile, network down).
 * - 3: Scan completed partially because some advisory information was unavailable from upstream.
 */
export const CLI_EXIT_CODES = {
  CLEAN: 0,
  VULNERABLE: 1,
  FAILED: 2,
  PARTIAL: 3
} as const;

export type CliExitCode = (typeof CLI_EXIT_CODES)[keyof typeof CLI_EXIT_CODES];

/**
 * Maps scan summary status to a predictable CLI exit code.
 */
export function determineExitCode(summary: DependencyScanSummary): CliExitCode {
  switch (summary.scanStatus) {
    case 'FAILED':
      return CLI_EXIT_CODES.FAILED; // 2
    case 'PARTIAL':
      return CLI_EXIT_CODES.PARTIAL; // 3
    case 'VULNERABLE':
      return CLI_EXIT_CODES.VULNERABLE; // 1
    case 'CLEAN':
    default:
      return CLI_EXIT_CODES.CLEAN; // 0
  }
}

/**
 * Maps secret scan summary status to a predictable CLI exit code.
 */
export function determineSecretExitCode(summary: SecretScanSummary): CliExitCode {
  switch (summary.scanStatus) {
    case 'FAILED':
      return CLI_EXIT_CODES.FAILED; // 2
    case 'PARTIAL':
      return CLI_EXIT_CODES.PARTIAL; // 3
    case 'VULNERABLE':
      return CLI_EXIT_CODES.VULNERABLE; // 1
    case 'CLEAN':
    default:
      return CLI_EXIT_CODES.CLEAN; // 0
  }
}

export function formatSeverityBadge(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return chalk.bgRed.white.bold(' CRITICAL ');
    case 'HIGH':
      return chalk.bgHex('#FF5722').white.bold('   HIGH   ');
    case 'MODERATE':
      return chalk.bgYellow.black.bold(' MODERATE ');
    case 'LOW':
      return chalk.bgCyan.black.bold('   LOW    ');
    case 'UNKNOWN':
    default:
      return chalk.bgGray.white.bold(' UNKNOWN  ');
  }
}

export async function runSecurityDeps(
  targetPath?: string,
  options: SecurityDepsCommandOptions = {}
): Promise<DependencyScanResult> {
  const result = await scanDependencies({ cwd: targetPath });
  const exitCode = determineExitCode(result.summary);

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = exitCode;
    return result;
  }

  const { summary, findings } = result;

  console.log();
  console.log(chalk.bold.cyan(' DevPilot Security — Dependency Vulnerability Scanner'));
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    `${chalk.bold('Dependencies Checked:')} ${chalk.white(summary.totalDependencies)} total ` +
      chalk.gray(`(${summary.directCount} direct, ${summary.transitiveCount} transitive, ${summary.uniquePackages} unique packages)`)
  );
  console.log(
    `${chalk.bold('Scan Duration:')}        ${chalk.white(`${summary.durationMs}ms`)}`
  );

  // Failure state (Exit Code 2)
  if (summary.scanStatus === 'FAILED') {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.red.bold('✖ Scan Failed (Exit Code 2):') +
        ' ' +
        chalk.red(summary.errorMessage ?? 'An unknown error occurred during scanning.')
    );
    console.log(
      chalk.yellow('⚠ Caution: This scan could not be completed and must NOT be considered clean.')
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log();
    process.exitCode = exitCode;
    return result;
  }

  // Partial state (Exit Code 3)
  if (summary.scanStatus === 'PARTIAL') {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.yellow.bold('⚠ Scan Partially Completed (Exit Code 3):') +
        chalk.yellow(' One or more advisory records could not be fully retrieved from OSV.')
    );
    console.log(
      chalk.yellow('⚠ Caution: Due to incomplete upstream advisory data, this scan cannot be certified clean.')
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log();
    process.exitCode = exitCode;
    return result;
  }

  // Clean state (Exit Code 0)
  if (summary.scanStatus === 'CLEAN') {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.green.bold('✔ No Known Vulnerabilities Found (Exit Code 0)') +
        chalk.gray(` across ${summary.totalDependencies} installed dependencies.`)
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log();
    process.exitCode = exitCode;
    return result;
  }

  // Vulnerable state (Exit Code 1)
  console.log(
    `${chalk.bold('Vulnerable Packages:')}  ${chalk.red.bold(String(summary.vulnerableDependencies))}`
  );
  console.log(
    `${chalk.bold('Total Findings:')}       ${chalk.red.bold(String(summary.findingsCount))}`
  );
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
  console.log(chalk.bold('Advisory Details:'));
  console.log();

  findings.forEach((finding, idx) => {
    const badge = formatSeverityBadge(finding.severity);
    const depTypeLabel =
      finding.dependencyType === 'direct'
        ? chalk.magenta.bold('(direct)')
        : chalk.gray('(transitive)');
    const optionalLabel = finding.isOptional ? chalk.gray(' [optional]') : '';

    console.log(
      `${chalk.bold(`${idx + 1}.`)} ${badge} ${chalk.bold.white(finding.packageName)}@${chalk.yellow(finding.installedVersion)} ${depTypeLabel}${optionalLabel}`
    );
    console.log(
      `   ${chalk.bold('Vulnerability:')} ${chalk.cyan(finding.vulnerabilityId)}${
        finding.aliases.length > 0
          ? chalk.gray(` (aliases: ${finding.aliases.filter((a) => a !== finding.vulnerabilityId).join(', ')})`)
          : ''
      }`
    );

    // CVSS Display with version, score, and source transparency
    if (finding.cvssVector || finding.cvssScore) {
      const cvssVer = finding.cvssVersion ? `CVSS v${finding.cvssVersion}` : 'CVSS';
      const scoreStr = finding.cvssScore ? chalk.yellow.bold(finding.cvssScore) : '';
      const vectorStr = finding.cvssVector ? chalk.gray(`(${finding.cvssVector})`) : '';

      let sourceNote = '';
      if (finding.severitySource === 'database_specific') {
        sourceNote = chalk.gray(' [severity: OSV advisory database]');
      } else if (finding.severitySource === 'calculated_cvss3') {
        sourceNote = chalk.gray(' [severity: calculated from CVSS v3 vector]');
      } else if (finding.severitySource === 'explicit_score') {
        sourceNote = chalk.gray(' [severity: advisory source score]');
      } else if (finding.cvssVersion === '4.0') {
        sourceNote = chalk.gray(' [CVSS v4 vector preserved; qualitative rating from source]');
      }

      const scoreAndVector = [scoreStr, vectorStr].filter(Boolean).join(' ');
      console.log(
        `   ${chalk.bold(`${cvssVer}:`)}${' '.repeat(Math.max(1, 14 - cvssVer.length))}${scoreAndVector}${sourceNote}`
      );
    }

    console.log(`   ${chalk.bold('Summary:')}       ${finding.title}`);
    console.log(`   ${chalk.bold('Evidence:')}      ${chalk.gray(finding.evidence)}`);
    console.log(
      `   ${chalk.bold('Fixed in:')}      ${
        finding.fixedVersions.length > 0
          ? chalk.green.bold(finding.fixedVersions.join(', '))
          : chalk.yellow('No fixed version specified')
      }`
    );
    console.log(`   ${chalk.bold('Remediation:')}   ${chalk.green(finding.remediation)}`);

    if (finding.isIncomplete) {
      console.log(
        `   ${chalk.yellow.bold('Notice:')}        ${chalk.yellow('Full advisory details could not be retrieved from OSV (using minimal metadata).')}`
      );
    }

    if (finding.references.length > 0) {
      console.log(
        `   ${chalk.bold('References:')}    ${chalk.blue.underline(finding.references[0])}`
      );
    }
    console.log();
  });

  if (summary.hasIncompleteAdvisories) {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.yellow.bold('⚠ Partial Hydration Notice:') +
        chalk.yellow(' Some advisory details could not be retrieved due to network or upstream rate limits.')
    );
  }

  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    chalk.yellow.bold('ℹ Remediation Guidance:') +
      chalk.white(
        ' Prioritize CRITICAL and HIGH severities. For transitive dependencies, update parent manifests or configure dependency overrides.'
      )
  );
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log();

  process.exitCode = exitCode;
  return result;
}

export interface SecuritySecretsCommandOptions {
  json?: boolean;
}

export async function runSecuritySecrets(
  targetPath?: string,
  options: SecuritySecretsCommandOptions = {}
): Promise<SecretScanResult> {
  const result = await scanSecrets({ cwd: targetPath });
  const exitCode = determineSecretExitCode(result.summary);

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = exitCode;
    return result;
  }

  const { summary, findings } = result;
  const resolvedTarget = targetPath ? path.resolve(targetPath) : process.cwd();

  console.log();
  console.log(chalk.bold.cyan(' DevPilot Security — Secret Scanner'));
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    `${chalk.bold('Target Path:')}          ${chalk.white(resolvedTarget)}`
  );
  console.log(
    `${chalk.bold('Files Scanned:')}        ${chalk.white(summary.totalFilesScanned)}`
  );
  console.log(
    `${chalk.bold('Lines Scanned:')}        ${chalk.white(summary.totalLinesScanned)}`
  );
  console.log(
    `${chalk.bold('Scan Duration:')}        ${chalk.white(`${summary.durationMs}ms`)}`
  );
  console.log(
    `${chalk.bold('Files Filtered:')}       ${chalk.gray(`${summary.intentionalSkippedCount} intentionally excluded, ${summary.errorSkippedCount} error-skipped`)}`
  );

  // Failure state (Exit Code 2)
  if (summary.scanStatus === 'FAILED') {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.red.bold('✖ Scan Failed (Exit Code 2):') +
        ' ' +
        chalk.red(summary.errorMessage ?? 'An unrecoverable error occurred during secret scanning.')
    );
    console.log(
      chalk.yellow('⚠ Caution: This scan could not be completed and must NOT be considered clean.')
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log();
    process.exitCode = exitCode;
    return result;
  }

  // Partial notice (Exit Code 3)
  if (summary.scanStatus === 'PARTIAL') {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.yellow.bold('⚠ Scan Partially Completed (Exit Code 3):') +
        chalk.yellow(` ${summary.errorSkippedCount} file(s) could not be read or exceeded size limits.`)
    );
    console.log(
      chalk.yellow('⚠ Caution: Some eligible files were skipped due to I/O or size errors; this scan cannot be certified clean.')
    );
    const errorFiles = summary.skippedFiles.filter((f) => !f.isIntentionallyExcluded);
    if (errorFiles.length > 0) {
      console.log(chalk.yellow('  Skipped error files:'));
      errorFiles.slice(0, 10).forEach((f) => {
        console.log(chalk.yellow(`   - ${f.filePath} (${f.reason}${f.details ? `: ${f.details}` : ''})`));
      });
      if (errorFiles.length > 10) {
        console.log(chalk.yellow(`   ... and ${errorFiles.length - 10} more`));
      }
    }
  }

  // Clean state (Exit Code 0)
  if (summary.scanStatus === 'CLEAN') {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.green.bold('✔ No Secrets Detected (Exit Code 0)') +
        chalk.gray(` across ${summary.totalFilesScanned} scanned files (${summary.totalLinesScanned} lines).`)
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log();
    process.exitCode = exitCode;
    return result;
  }

  // Vulnerable or Partial-with-findings (Exit Code 1 or 3)
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    `${chalk.bold('Total Findings:')}       ${chalk.red.bold(String(summary.findingsCount))}`
  );
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
  console.log(chalk.bold('Detected Secrets:'));
  console.log();

  findings.forEach((finding, idx) => {
    const badge = formatSeverityBadge(finding.severity);
    const location = chalk.white.bold(`${finding.packageName}:${finding.installedVersion}`);

    console.log(`${chalk.bold(`${idx + 1}.`)} ${badge} ${location}`);
    console.log(`   ${chalk.bold('Rule ID:')}      ${chalk.cyan(finding.vulnerabilityId)}`);
    console.log(`   ${chalk.bold('Description:')}  ${finding.title}`);
    console.log(`   ${chalk.bold('Evidence:')}     ${chalk.gray(finding.evidence)}`);
    if (finding.remediationDetails?.notes) {
      console.log(
        `   ${chalk.bold('Masked:')}       ${chalk.yellow(
          finding.remediationDetails.notes.replace('Secret value masked: ', '')
        )}`
      );
    }
    console.log(`   ${chalk.bold('Remediation:')}  ${chalk.green(finding.remediation)}`);
    console.log();
  });

  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    chalk.yellow.bold('ℹ Remediation Guidance:') +
      chalk.white(
        ' Revoke and rotate exposed credentials immediately. Remove secrets from code and Git history (e.g., git-filter-repo). Store secrets in environment variables or a dedicated secrets manager.'
      )
  );
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log();

  process.exitCode = exitCode;
  return result;
}

/**
 * Maps SAST scan summary status to a predictable CLI exit code.
 */
export function determineSastExitCode(summary: SastScanSummary): CliExitCode {
  switch (summary.scanStatus) {
    case 'FAILED':
      return CLI_EXIT_CODES.FAILED; // 2
    case 'PARTIAL':
      return CLI_EXIT_CODES.PARTIAL; // 3
    case 'VULNERABLE':
      return CLI_EXIT_CODES.VULNERABLE; // 1
    case 'CLEAN':
    default:
      return CLI_EXIT_CODES.CLEAN; // 0
  }
}

/**
 * Executes the `devpilot security sast [path]` command.
 */
export async function runSecuritySast(
  targetPath?: string,
  options: SecuritySastCommandOptions = {}
): Promise<SastScanResult> {
  const result = await scanSast({ cwd: targetPath });
  const exitCode = determineSastExitCode(result.summary);

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = exitCode;
    return result;
  }

  const { summary, findings } = result;

  console.log();
  console.log(chalk.bold.cyan(' DevPilot Security — Static Application Security Testing (SAST)'));
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    `${chalk.bold('Target Path:')}          ${chalk.green(path.resolve(targetPath ?? process.cwd()))}`
  );
  console.log(
    `${chalk.bold('Files Scanned:')}        ${chalk.white(String(summary.totalFilesScanned))}`
  );
  console.log(
    `${chalk.bold('Lines Scanned:')}        ${chalk.white(String(summary.totalLinesScanned))}`
  );
  console.log(
    `${chalk.bold('Scan Duration:')}        ${chalk.white(`${summary.durationMs}ms`)}`
  );
  console.log(
    `${chalk.bold('Files Filtered:')}       ${chalk.white(
      `${summary.intentionalSkippedCount} excluded, ${summary.errorSkippedCount} skipped`
    )}`
  );

  if (summary.scanStatus === 'CLEAN') {
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.green.bold(
        `✔ No Security Issues Detected (Exit Code 0) across ${summary.totalFilesScanned} scanned files (${summary.totalLinesScanned} lines).`
      )
    );
    console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
    console.log();
    process.exitCode = exitCode;
    return result;
  }

  // Vulnerable or Partial (Exit Code 1 or 3)
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    `${chalk.bold('Total Findings:')}       ${chalk.red.bold(String(summary.findingsCount))}`
  );
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
  console.log(chalk.bold('Detected SAST Issues:'));
  console.log();

  findings.forEach((finding, idx) => {
    const badge = formatSeverityBadge(finding.severity);
    const locStr = finding.location
      ? `${finding.location.filePath}:${finding.location.line}:${finding.location.column}`
      : `${finding.packageName}:${finding.installedVersion}`;
    const location = chalk.white.bold(locStr);

    console.log(`${chalk.bold(`${idx + 1}.`)} ${badge} ${location}`);
    console.log(`   ${chalk.bold('Rule ID:')}      ${chalk.cyan(finding.vulnerabilityId)}`);
    console.log(`   ${chalk.bold('Description:')}  ${finding.title}`);
    console.log(`   ${chalk.bold('Evidence:')}     ${chalk.gray(finding.evidence)}`);
    console.log(`   ${chalk.bold('Remediation:')}  ${chalk.green(finding.remediation)}`);
    console.log();
  });

  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log(
    chalk.yellow.bold('ℹ Remediation Guidance:') +
      chalk.white(
        ' Address CRITICAL and HIGH severity code security issues before deploying to production.'
      )
  );
  console.log(chalk.gray('──────────────────────────────────────────────────────────────────────'));
  console.log();

  process.exitCode = exitCode;
  return result;
}

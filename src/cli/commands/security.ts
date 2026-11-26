import chalk from 'chalk';
import type { SeverityLevel } from '../../core/finding.js';
import { scanDependencies } from '../../scanners/dependency/dependency-scanner.js';
import type { DependencyScanResult, DependencyScanSummary } from '../../scanners/dependency/types.js';

export interface SecurityDepsCommandOptions {
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

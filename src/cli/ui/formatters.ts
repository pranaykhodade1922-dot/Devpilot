import chalk from 'chalk';
import type { SecurityFinding, SeverityLevel } from '../../core/finding.js';
import {
  BRAND_CONSTANTS,
  DIVIDER_LENGTHS,
  SEVERITY_PLAIN_TAGS,
  TERMINAL_SYMBOLS,
  ASCII_TERMINAL_SYMBOLS,
  getStyledSeverityBadge,
  getStyledScannerBadge
} from './theme.js';
import { stripAnsi, shouldUseColor } from './terminal.js';

export interface FormatterOptions {
  color?: boolean;
}

export interface BannerOptions extends FormatterOptions {
  version?: string;
  targetPath?: string;
}

export interface ScanSummaryData {
  projectName?: string;
  projectRoot?: string;
  framework?: string;
  language?: string;
  packageManager?: string;
  totalFindings: number;
  severityCounts: Record<SeverityLevel, number>;
  scanStatus: 'CLEAN' | 'VULNERABLE' | 'PARTIAL' | 'FAILED';
  durationMs: number;
}

/**
 * Returns a terminal divider of specified length.
 */
export function formatDivider(length = DIVIDER_LENGTHS.full, options?: FormatterOptions): string {
  const line = '─'.repeat(length);
  const useColor = options?.color ?? shouldUseColor();
  return useColor ? chalk.gray(line) : line;
}

/**
 * Formats a clean, high-legibility startup banner with the DevPilot Security logo.
 */
export function formatBanner(options?: BannerOptions): string {
  const useColor = options?.color ?? shouldUseColor();
  const version = options?.version ?? '0.1.0';
  const targetPath = options?.targetPath;

  const sym = useColor ? TERMINAL_SYMBOLS.diamond : ASCII_TERMINAL_SYMBOLS.diamond;

  const rawLines = [
    `┌───┐  ${BRAND_CONSTANTS.name} v${version}`,
    `│ ${sym} │  ${BRAND_CONSTANTS.tagline}`,
    `└───┘` + (targetPath ? `  Target: ${targetPath}` : '')
  ];

  if (!useColor) {
    return rawLines.map(stripAnsi).join('\n');
  }

  return [
    `${chalk.cyan('┌───┐')}  ${chalk.bold.cyan(BRAND_CONSTANTS.name)} ${chalk.gray(`v${version}`)}`,
    `${chalk.cyan('│')} ${chalk.yellow(sym)} ${chalk.cyan('│')}  ${chalk.dim(BRAND_CONSTANTS.tagline)}`,
    `${chalk.cyan('└───┘')}` + (targetPath ? `  ${chalk.dim('Target:')} ${chalk.white(targetPath)}` : '')
  ].join('\n');
}

/**
 * Formats a uniform severity badge (colored ANSI or plain text).
 */
export function formatSeverityBadge(severity: SeverityLevel, options?: FormatterOptions): string {
  const useColor = options?.color ?? shouldUseColor();
  if (!useColor) {
    return SEVERITY_PLAIN_TAGS[severity] ?? SEVERITY_PLAIN_TAGS.UNKNOWN;
  }
  return getStyledSeverityBadge(severity);
}

/**
 * Formats a uniform scanner badge (colored ANSI or plain text).
 */
export function formatScannerBadge(scanner: string, options?: FormatterOptions): string {
  const useColor = options?.color ?? shouldUseColor();
  if (!useColor) {
    switch (scanner) {
      case 'secret-scanner':
        return '[SECRET]';
      case 'sast-scanner':
        return '[SAST]';
      case 'dependency-scanner':
      default:
        return '[DEPENDENCY]';
    }
  }
  return getStyledScannerBadge(scanner);
}

/**
 * Formats a single finding card heading: e.g. "1.  CRITICAL   SAST  src/db.ts:14:12"
 */
export function formatFindingHeader(
  index: number,
  finding: SecurityFinding,
  options?: FormatterOptions
): string {
  const useColor = options?.color ?? shouldUseColor();
  const badge = formatSeverityBadge(finding.severity, { color: useColor });
  const scannerBadge = formatScannerBadge(finding.scanner, { color: useColor });

  const location = finding.location
    ? `${finding.location.filePath}:${finding.location.line}:${finding.location.column}`
    : `${finding.packageName} ${finding.installedVersion}`;

  const prefix = `${index}.`;
  if (!useColor) {
    return `${prefix} ${badge} ${scannerBadge} ${location}`;
  }

  return `${chalk.bold(prefix)} ${badge} ${scannerBadge} ${chalk.white.bold(location)}`;
}

/**
 * Formats a section header with standard styling.
 */
export function formatSectionHeader(title: string, options?: FormatterOptions): string {
  const useColor = options?.color ?? shouldUseColor();
  if (!useColor) {
    return title;
  }
  return chalk.bold(title);
}

/**
 * Formats the final scan summary status block (severity breakdown or clean confirmation).
 */
export function formatScanSummarySection(
  summary: ScanSummaryData,
  options?: FormatterOptions
): string {
  const useColor = options?.color ?? shouldUseColor();
  const divider = formatDivider(DIVIDER_LENGTHS.full, { color: useColor });
  const lines: string[] = [];

  lines.push(divider);

  if (summary.scanStatus === 'CLEAN') {
    const sym = useColor ? TERMINAL_SYMBOLS.check : ASCII_TERMINAL_SYMBOLS.check;
    const msg = `${sym} Scan Completed: Clean (Exit Code 0)`;
    lines.push(useColor ? chalk.green.bold(msg) : msg);
    lines.push(
      useColor
        ? chalk.gray('  0 vulnerabilities, 0 secrets, and 0 code security issues detected.')
        : '  0 vulnerabilities, 0 secrets, and 0 code security issues detected.'
    );
  } else if (summary.scanStatus === 'FAILED') {
    const sym = useColor ? TERMINAL_SYMBOLS.cross : ASCII_TERMINAL_SYMBOLS.cross;
    const msg = `${sym} Scan Failed (Exit Code 2)`;
    lines.push(useColor ? chalk.red.bold(msg) : msg);
    lines.push(
      useColor
        ? chalk.yellow('  One or more security scanners encountered fatal errors.')
        : '  One or more security scanners encountered fatal errors.'
    );
  } else if (summary.scanStatus === 'PARTIAL') {
    const sym = useColor ? TERMINAL_SYMBOLS.warning : ASCII_TERMINAL_SYMBOLS.warning;
    const msg = `${sym} Scan Partially Completed (Exit Code 3)`;
    lines.push(useColor ? chalk.yellow.bold(msg) : msg);
    lines.push(
      useColor
        ? chalk.yellow('  Some files had syntax errors, unreadable contents, or incomplete advisories.')
        : '  Some files had syntax errors, unreadable contents, or incomplete advisories.'
    );
  } else {
    // VULNERABLE
    const counts = summary.severityCounts;
    const totalMsg = `Total Findings: ${summary.totalFindings}  (${summary.durationMs}ms total duration)`;
    lines.push(useColor ? chalk.bold(totalMsg) : totalMsg);

    const breakdown = [
      `CRITICAL: ${counts.CRITICAL}`,
      `HIGH: ${counts.HIGH}`,
      `MODERATE: ${counts.MODERATE}`,
      `LOW: ${counts.LOW}`,
      `UNKNOWN: ${counts.UNKNOWN}`
    ].join('  ');

    lines.push(useColor ? chalk.gray(`  ${breakdown}`) : `  ${breakdown}`);
  }

  lines.push(divider);
  return lines.join('\n');
}

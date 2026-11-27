import chalk from 'chalk';
import type { SeverityLevel } from '../../core/finding.js';

export const BRAND_CONSTANTS = {
  name: 'DevPilot Security',
  tagline: 'Developer security toolkit for modern applications',
  slogan: 'Built for developers, by developers.',
  repositoryUrl: 'https://github.com/pranaykhodade1922-dot/Devpilot'
} as const;

export const DIVIDER_LENGTHS = {
  full: 70,
  compact: 50,
  about: 44
} as const;

export const TERMINAL_SYMBOLS = {
  check: '✔',
  cross: '✖',
  warning: '⚠',
  info: 'ℹ',
  bullet: '•',
  arrow: '→',
  diamond: '◆'
} as const;

export const ASCII_TERMINAL_SYMBOLS = {
  check: '[v]',
  cross: '[x]',
  warning: '[!]',
  info: '[i]',
  bullet: '*',
  arrow: '->',
  diamond: '*'
} as const;

export const SEVERITY_BADGE_TEXT: Record<SeverityLevel, string> = {
  CRITICAL: ' CRITICAL ',
  HIGH:     '   HIGH   ',
  MODERATE: ' MODERATE ',
  LOW:      '   LOW    ',
  UNKNOWN:  ' UNKNOWN  '
};

export const SEVERITY_PLAIN_TAGS: Record<SeverityLevel, string> = {
  CRITICAL: '[CRITICAL]',
  HIGH:     '[HIGH]',
  MODERATE: '[MODERATE]',
  LOW:      '[LOW]',
  UNKNOWN:  '[UNKNOWN]'
};

/**
 * Returns a styled severity badge with background color.
 */
export function getStyledSeverityBadge(severity: SeverityLevel): string {
  const text = SEVERITY_BADGE_TEXT[severity] ?? SEVERITY_BADGE_TEXT.UNKNOWN;
  switch (severity) {
    case 'CRITICAL':
      return chalk.bgRed.white.bold(text);
    case 'HIGH':
      return chalk.bgHex('#FF5722').white.bold(text);
    case 'MODERATE':
      return chalk.bgYellow.black.bold(text);
    case 'LOW':
      return chalk.bgCyan.black.bold(text);
    case 'UNKNOWN':
    default:
      return chalk.bgGray.white.bold(text);
  }
}

/**
 * Returns a styled scanner type badge.
 */
export function getStyledScannerBadge(scanner: string): string {
  switch (scanner) {
    case 'secret-scanner':
      return chalk.bgHex('#7B1FA2').white.bold(' SECRET ');
    case 'sast-scanner':
      return chalk.bgHex('#D84315').white.bold(' SAST ');
    case 'dependency-scanner':
    default:
      return chalk.bgHex('#1565C0').white.bold(' DEPENDENCY ');
  }
}

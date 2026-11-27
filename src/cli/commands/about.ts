import chalk from 'chalk';
import { getPackageMetadata, type PackageMetadata } from '../../utils/version.js';

export interface AboutInfo {
  projectName: string;
  description: string;
  mission: string;
  founderName: string;
  founderTitle: string;
  version: string;
  repositoryUrl: string;
  license?: string;
}

/**
 * Returns structured about information for DevPilot Security.
 * Accepts optional custom metadata overrides for deterministic testing.
 */
export function getAboutInfo(customMetadata?: Partial<PackageMetadata>): AboutInfo {
  const metadata = customMetadata ?? getPackageMetadata();

  return {
    projectName: 'DevPilot Security',
    description: 'A developer-friendly security toolkit for modern applications.',
    mission: 'Help developers identify, understand, and fix security issues in their projects.',
    founderName: 'Pranay Khodade',
    founderTitle: 'Founder & Creator',
    version: metadata.version ?? '0.1.0',
    repositoryUrl: 'https://github.com/pranaykhodade1922-dot/Devpilot',
    license: metadata.license
  };
}

/**
 * Formats clean, professional terminal output for the about command.
 */
export function formatAboutOutput(info: AboutInfo): string {
  const divider = chalk.gray('────────────────────────────────────────────');

  const lines: string[] = [
    divider,
    chalk.cyan.bold('             DEVPILOT SECURITY'),
    divider,
    '',
    'A developer-friendly security toolkit\nfor modern applications.',
    '',
    chalk.bold.yellow('CREATED BY'),
    chalk.bold.white(info.founderName),
    chalk.dim(info.founderTitle),
    '',
    chalk.bold.yellow('PROJECT'),
    `${chalk.dim('Version:      ')} ${chalk.green(info.version)}`,
    `${chalk.dim('Repository:   ')} ${chalk.cyan(info.repositoryUrl)}`
  ];

  if (info.license) {
    lines.push(`${chalk.dim('License:      ')} ${chalk.green(info.license)}`);
  }

  lines.push(
    '',
    chalk.bold.yellow('OUR MISSION'),
    'Help developers identify, understand,\nand fix security issues in their projects.',
    '',
    divider,
    chalk.cyan('       Built for developers, by developers.'),
    divider
  );

  return lines.join('\n');
}

/**
 * Executes the `devpilot about` command.
 */
export function runAbout(): void {
  const info = getAboutInfo();
  console.log(formatAboutOutput(info));
}

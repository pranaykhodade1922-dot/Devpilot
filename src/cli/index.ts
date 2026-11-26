#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { getDevPilotVersion } from '../utils/version.js';
import { runDoctor } from './commands/doctor.js';
import { runScan } from './commands/scan.js';
import { runSecurityDeps } from './commands/security.js';

export function createProgram(): Command {
  const program = new Command();

  program
    .name('devpilot')
    .description(
      `${chalk.cyan.bold('DevPilot Security')} — Developer security toolkit for modern applications`
    )
    .version(getDevPilotVersion(), '-v, --version', 'Displays the current CLI version');

  program
    .command('doctor')
    .description('Checks the local DevPilot environment and dependencies')
    .action(() => {
      runDoctor();
    });

  program
    .command('scan [path]')
    .description('Detects the current project and displays project metadata')
    .action((targetPath?: string) => {
      runScan(targetPath);
    });

  const security = program
    .command('security')
    .description('Security analysis and vulnerability scanning commands');

  security
    .command('deps [path]')
    .description('Scan project dependencies for known security vulnerabilities via OSV')
    .option('--json', 'Output scan results as machine-readable JSON')
    .action(async (targetPath?: string, options?: { json?: boolean }) => {
      await runSecurityDeps(targetPath, options);
    });

  return program;
}

export async function runCLI(argv = process.argv): Promise<void> {
  const program = createProgram();

  try {
    await program.parseAsync(argv);
  } catch (error) {
    console.error(
      chalk.red('Error:'),
      error instanceof Error ? error.message : String(error)
    );
    process.exit(1);
  }
}

// Execute CLI
runCLI();

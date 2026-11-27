#!/usr/bin/env node
import { Command, Help } from 'commander';
import chalk from 'chalk';
import { getDevPilotVersion } from '../utils/version.js';
import { runAbout } from './commands/about.js';
import { runDoctor } from './commands/doctor.js';
import { runScan } from './commands/scan.js';
import { runSecurityDeps, runSecuritySecrets, runSecuritySast } from './commands/security.js';

export function createProgram(): Command {
  const program = new Command();
  const defaultHelp = new Help();

  program
    .name('devpilot')
    .description(
      `${chalk.cyan.bold('DevPilot Security')} — Developer security toolkit for modern applications`
    )
    .version(getDevPilotVersion(), '-v, --version', 'Displays the current CLI version');

  program.configureHelp({
    formatHelp: (cmd) => {
      if (cmd === program) {
        return [
          `Usage: devpilot [options] [command]`,
          ``,
          `${chalk.cyan.bold('DevPilot Security')} — Developer security toolkit for modern applications`,
          ``,
          `Options:`,
          `  -v, --version                Displays the current CLI version`,
          `  -h, --help                   display help for command`,
          ``,
          `MAIN COMMANDS`,
          `  scan [path]                  Run unified security scan (dependencies + secrets)`,
          ``,
          `SECURITY COMMANDS`,
          `  security deps [path]         Scan project dependencies for known vulnerabilities via OSV`,
          `  security secrets [path]      Scan project files for hardcoded secrets, API keys, and credentials`,
          `  security sast [path]         Scan source code for static application security vulnerabilities`,
          ``,
          `UTILITY COMMANDS`,
          `  about                        Show information about DevPilot Security and its founder`,
          `  doctor                       Checks the local DevPilot environment and dependencies`,
          `  help [command]               Display help for command`,
          ``,
          `EXAMPLES`,
          `  $ devpilot scan`,
          `  $ devpilot scan ./my-project`,
          `  $ devpilot security deps`,
          `  $ devpilot security secrets --json`,
          `  $ devpilot doctor`,
          `  $ devpilot about`,
          ``
        ].join('\n');
      }

      if (cmd.name() === 'scan') {
        const base = defaultHelp.formatHelp(cmd, defaultHelp);
        return [
          base,
          `Examples:`,
          `  $ devpilot scan`,
          `  $ devpilot scan ./my-project`,
          `  $ devpilot scan --json`,
          ``
        ].join('\n');
      }

      return defaultHelp.formatHelp(cmd, defaultHelp);
    }
  });

  program
    .command('about')
    .description('Show information about DevPilot Security and its founder')
    .action(() => {
      runAbout();
    });

  program
    .command('doctor')
    .description('Checks the local DevPilot environment and dependencies')
    .action(() => {
      runDoctor();
    });

  program
    .command('scan [path]')
    .description('Run unified security scan across project dependencies and source files')
    .option('--json', 'Output scan results as machine-readable JSON')
    .addHelpText(
      'after',
      `
Examples:
  $ devpilot scan
  $ devpilot scan ./my-project
  $ devpilot scan --json`
    )
    .action(async (targetPath?: string, options?: { json?: boolean }) => {
      await runScan(targetPath, options);
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

  security
    .command('secrets [path]')
    .description('Scan project files for hardcoded secrets, API keys, and credentials')
    .option('--json', 'Output scan results as machine-readable JSON')
    .action(async (targetPath?: string, options?: { json?: boolean }) => {
      await runSecuritySecrets(targetPath, options);
    });

  security
    .command('sast [path]')
    .description('Scan source code for static application security vulnerabilities')
    .option('--json', 'Output scan results as machine-readable JSON')
    .action(async (targetPath?: string, options?: { json?: boolean }) => {
      await runSecuritySast(targetPath, options);
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

// Execute CLI when not running inside test environment
if (!process.env.VITEST && process.env.NODE_ENV !== 'test') {
  runCLI();
}

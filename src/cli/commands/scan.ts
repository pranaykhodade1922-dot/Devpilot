import chalk from 'chalk';
import { detectProject } from '../../core/project-detector.js';

export function runScan(targetPath?: string): void {
  const project = detectProject({ cwd: targetPath });

  console.log();
  console.log(chalk.bold.cyan(' DevPilot Security — Project Inspector'));
  console.log(chalk.gray('──────────────────────────────────────────────────'));
  console.log(`${chalk.bold('Project Name:')}        ${chalk.green(project.projectName)}`);
  console.log(`${chalk.bold('Project Root:')}        ${chalk.green(project.projectRoot)}`);
  console.log(
    `${chalk.bold('package.json:')}        ${
      project.packageJsonExists
        ? chalk.green('✔ Found')
        : chalk.yellow('✘ Missing (no package.json detected)')
    }`
  );

  if (project.details.isMalformedPackageJson) {
    console.log(
      `${chalk.bold('package.json Status:')} ${chalk.red('⚠ Malformed JSON or invalid format')}`
    );
  }

  console.log(
    `${chalk.bold('Package Manager:')}     ${
      project.packageManager !== 'None detected'
        ? chalk.green(project.packageManager)
        : chalk.yellow('None detected')
    }`
  );
  console.log(
    `${chalk.bold('Detected Language:')}   ${
      project.language === 'TypeScript'
        ? chalk.blue.bold('TypeScript')
        : project.language === 'JavaScript'
          ? chalk.yellow.bold('JavaScript')
          : chalk.gray('Unknown')
    }`
  );
  console.log(
    `${chalk.bold('Detected Framework:')}  ${
      project.framework !== 'None detected'
        ? chalk.magenta.bold(project.framework)
        : chalk.gray('None detected')
    }`
  );
  console.log(chalk.gray('──────────────────────────────────────────────────'));
  console.log(
    chalk.yellow.bold('ℹ Notice:') +
      chalk.white(
        ' Security scanning (vulnerability detection, secret scanning, and code analysis) is scheduled for the next development phase.'
      )
  );
  console.log(
    chalk.gray("Run 'devpilot --help' to see all available commands in this release.")
  );
  console.log();
}

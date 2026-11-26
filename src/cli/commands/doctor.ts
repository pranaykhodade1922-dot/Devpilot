import os from 'node:os';
import chalk from 'chalk';
import { getDevPilotVersion } from '../../utils/version.js';

export interface DoctorResult {
  devPilotVersion: string;
  nodeVersion: string;
  osPlatform: string;
  osRelease: string;
  osArch: string;
  cwd: string;
  isNodeSupported: boolean;
  environmentStatus: string;
}

export function getDoctorInfo(): DoctorResult {
  const devPilotVersion = getDevPilotVersion();
  const nodeVersion = process.version;
  const osPlatform = process.platform;
  const osRelease = os.release();
  const osArch = process.arch;
  const cwd = process.cwd();

  const majorNode = parseInt(process.versions.node.split('.')[0] ?? '0', 10);
  const isNodeSupported = majorNode >= 18;
  const environmentStatus = isNodeSupported ? 'Ready / Operational' : 'Node.js >= 18 is required';

  return {
    devPilotVersion,
    nodeVersion,
    osPlatform,
    osRelease,
    osArch,
    cwd,
    isNodeSupported,
    environmentStatus
  };
}

export function runDoctor(): void {
  const info = getDoctorInfo();

  console.log();
  console.log(chalk.bold.cyan(' DevPilot Security — Environment Doctor'));
  console.log(chalk.gray('──────────────────────────────────────────────────'));
  console.log(`${chalk.bold('DevPilot Version:')}    ${chalk.green(info.devPilotVersion)}`);
  console.log(`${chalk.bold('Node.js Version:')}     ${chalk.green(info.nodeVersion)}`);
  console.log(
    `${chalk.bold('Operating System:')}    ${chalk.green(`${info.osPlatform} (${info.osRelease}) ${info.osArch}`)}`
  );
  console.log(`${chalk.bold('Working Directory:')}   ${chalk.green(info.cwd)}`);
  console.log(
    `${chalk.bold('Environment Status:')}  ${
      info.isNodeSupported
        ? chalk.green.bold(`✔ ${info.environmentStatus}`)
        : chalk.yellow.bold(`⚠ ${info.environmentStatus}`)
    }`
  );
  console.log(chalk.gray('──────────────────────────────────────────────────'));
  console.log();
}

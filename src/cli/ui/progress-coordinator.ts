import chalk from 'chalk';
import type { DependencyProgressEvent } from '../../scanners/dependency/types.js';
import type { SecretProgressEvent } from '../../scanners/secret/types.js';
import type { SastProgressEvent } from '../../scanners/sast/types.js';
import {
  shouldUseColor,
  type TerminalDetectionOptions
} from './terminal.js';
import { TerminalPresenter, formatCounts } from './progress.js';

export type ScannerIdentifier = 'dependency' | 'secret' | 'sast';

export interface ScannerState {
  id: ScannerIdentifier;
  name: string;
  stage?: string;
  status?: string;
  outcome?: 'clean' | 'vulnerable';
  message?: string;
  completed?: number;
  total?: number;
  findingsCount?: number;
  isFinished: boolean;
  finalLabel?: string;
}

export interface ProgressCoordinatorOptions extends TerminalDetectionOptions {
  stream?: NodeJS.WriteStream & { isTTY?: boolean; columns?: number };
  silent?: boolean; // For JSON mode or quiet runs: suppresses all rendering completely
  enabledScanners?: ScannerIdentifier[];
}

export class ProgressCoordinator {
  private readonly presenter: TerminalPresenter;
  private readonly useColor: boolean;
  private readonly silent: boolean;
  private readonly scanners = new Map<ScannerIdentifier, ScannerState>();
  private activeScannerId: ScannerIdentifier | null = null;

  constructor(options: ProgressCoordinatorOptions = {}) {
    this.silent = Boolean(options.silent);
    this.useColor = shouldUseColor(options);
    this.presenter = new TerminalPresenter(options);

    const configured = options.enabledScanners ?? ['dependency', 'secret', 'sast'];
    const names: Record<ScannerIdentifier, string> = {
      dependency: 'Dependency Scanner',
      secret: 'Secret Scanner',
      sast: 'SAST Scanner'
    };

    for (const id of configured) {
      this.scanners.set(id, {
        id,
        name: names[id],
        isFinished: false
      });
    }
  }

  /**
   * Starts interactive animation if terminal permits.
   */
  public start(): void {
    if (this.silent) return;
    this.presenter.start(() => {
      this.renderCurrentState();
    });
  }

  /**
   * Stops animation and cleans up cursor.
   */
  public stop(): void {
    if (this.silent) return;
    this.presenter.stop();
  }

  /**
   * Dispatches dependency progress event to coordinator.
   */
  public onDependencyProgress(event: DependencyProgressEvent): void {
    if (this.silent) return;
    try {
      this.handleEvent('dependency', {
        stage: event.stage,
        status: event.status,
        outcome: event.outcome,
        message: event.message,
        completed: event.completed,
        total: event.total,
        findingsCount: event.metadata?.findingsCount
      });
    } catch {
      // Presentation errors must never disrupt scanner flow
    }
  }

  /**
   * Dispatches secret progress event to coordinator.
   */
  public onSecretProgress(event: SecretProgressEvent): void {
    if (this.silent) return;
    try {
      this.handleEvent('secret', {
        stage: event.stage,
        status: event.status,
        outcome: event.outcome,
        message: event.message,
        completed: event.completed,
        total: event.total,
        findingsCount: event.metadata?.findingsCount
      });
    } catch {
      // Presentation errors must never disrupt scanner flow
    }
  }

  /**
   * Dispatches SAST progress event to coordinator.
   */
  public onSastProgress(event: SastProgressEvent): void {
    if (this.silent) return;
    try {
      this.handleEvent('sast', {
        stage: event.stage,
        status: event.status,
        outcome: event.outcome,
        message: event.message,
        completed: event.completed,
        total: event.total,
        findingsCount: event.metadata?.findingsCount
      });
    } catch {
      // Presentation errors must never disrupt scanner flow
    }
  }

  /**
   * Marks a scanner as explicitly skipped (e.g. no package.json for dependency scanner).
   */
  public markSkipped(scannerId: ScannerIdentifier, reason: string): void {
    if (this.silent) return;
    try {
      const state = this.scanners.get(scannerId);
      if (!state) return;
      state.isFinished = true;
      state.status = 'skipped';
      state.message = reason;

      const sym = this.presenter.getSymbols();
      const skipLabel = this.useColor ? chalk.gray(sym.bullet) : sym.bullet;
      const name = this.useColor ? chalk.bold(state.name) : state.name;
      const note = this.useColor ? chalk.gray(`(Skipped: ${reason})`) : `(Skipped: ${reason})`;

      this.presenter.logPermanent(`  ${skipLabel} ${name} ${note}`);
    } catch {
      // ignore
    }
  }

  private handleEvent(
    scannerId: ScannerIdentifier,
    event: {
      stage: string;
      status: string;
      outcome?: 'clean' | 'vulnerable';
      message?: string;
      completed?: number;
      total?: number;
      findingsCount?: number;
    }
  ): void {
    let state = this.scanners.get(scannerId);
    if (!state) {
      const names: Record<ScannerIdentifier, string> = {
        dependency: 'Dependency Scanner',
        secret: 'Secret Scanner',
        sast: 'SAST Scanner'
      };
      state = { id: scannerId, name: names[scannerId], isFinished: false };
      this.scanners.set(scannerId, state);
    }

    state.stage = event.stage;
    state.status = event.status;
    state.outcome = event.outcome;
    state.completed = event.completed;
    state.total = event.total;
    if (event.findingsCount !== undefined) {
      state.findingsCount = event.findingsCount;
    }
    if (event.message) {
      state.message = event.message;
    }

    this.activeScannerId = scannerId;

    // Check if terminal event
    if (event.stage === 'completed' || event.status === 'failed' || event.status === 'partial') {
      if (event.stage === 'completed') {
        state.isFinished = true;
        this.emitFinalScannerLine(state);
        return;
      }
    }

    this.renderCurrentState();
  }

  private renderCurrentState(): void {
    if (!this.activeScannerId) return;
    const state = this.scanners.get(this.activeScannerId);
    if (!state || state.isFinished) return;

    const countText = formatCounts(state.completed, state.total);
    const activity = state.message ?? state.stage ?? 'scanning';
    const detail = countText ? `${activity} (${countText})` : activity;

    const formatted = this.useColor
      ? `${chalk.bold.cyan(state.name)}: ${chalk.white(detail)}`
      : `${state.name}: ${detail}`;

    this.presenter.updateLine(formatted);
  }

  private emitFinalScannerLine(state: ScannerState): void {
    const sym = this.presenter.getSymbols();
    let statusBadge: string;
    let detailText = '';

    const findings = state.findingsCount ?? 0;

    if (state.status === 'failed') {
      const icon = this.useColor ? chalk.red.bold(sym.cross) : sym.cross;
      statusBadge = this.useColor ? chalk.red.bold('FAILED') : 'FAILED';
      detailText = this.useColor ? chalk.red(state.message ?? 'Scan failed') : (state.message ?? 'Scan failed');
      this.presenter.logPermanent(`  ${icon} ${chalk.bold(state.name)} [${statusBadge}] — ${detailText}`);
      return;
    }

    if (state.status === 'partial') {
      const icon = this.useColor ? chalk.yellow.bold(sym.warning) : sym.warning;
      if (state.outcome === 'vulnerable' || findings > 0) {
        statusBadge = this.useColor ? chalk.yellow.bold('PARTIAL COVERAGE (VULNERABLE)') : 'PARTIAL COVERAGE (VULNERABLE)';
        detailText = this.useColor
          ? chalk.red(`${findings} issue(s) detected; incomplete coverage`)
          : `${findings} issue(s) detected; incomplete coverage`;
      } else {
        statusBadge = this.useColor ? chalk.yellow.bold('PARTIAL') : 'PARTIAL';
        detailText = this.useColor
          ? chalk.yellow('Incomplete coverage; cannot establish clean result')
          : 'Incomplete coverage; cannot establish clean result';
      }
      this.presenter.logPermanent(`  ${icon} ${chalk.bold(state.name)} [${statusBadge}] — ${detailText}`);
      return;
    }

    // Completed
    if (state.outcome === 'vulnerable' || findings > 0) {
      const icon = this.useColor ? chalk.red.bold(sym.cross) : sym.cross;
      statusBadge = this.useColor ? chalk.red.bold('VULNERABLE') : 'VULNERABLE';
      detailText = this.useColor
        ? chalk.red(`${findings} issue(s) found`)
        : `${findings} issue(s) found`;
      this.presenter.logPermanent(`  ${icon} ${chalk.bold(state.name)} [${statusBadge}] — ${detailText}`);
    } else {
      const icon = this.useColor ? chalk.green.bold(sym.check) : sym.check;
      statusBadge = this.useColor ? chalk.green.bold('CLEAN') : 'CLEAN';
      detailText = this.useColor ? chalk.gray('0 issues detected') : '0 issues detected';
      this.presenter.logPermanent(`  ${icon} ${chalk.bold(state.name)} [${statusBadge}] — ${detailText}`);
    }
  }
}

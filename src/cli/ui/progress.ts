import chalk from 'chalk';
import {
  TERMINAL_SYMBOLS,
  ASCII_TERMINAL_SYMBOLS
} from './theme.js';
import {
  shouldAnimate,
  shouldUseColor,
  type TerminalDetectionOptions
} from './terminal.js';

export interface SpinnerFrameSet {
  frames: string[];
  interval: number;
}

export const SPINNER_FRAMES_UNICODE: SpinnerFrameSet = {
  frames: ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
  interval: 80
};

export const SPINNER_FRAMES_ASCII: SpinnerFrameSet = {
  frames: ['-', '\\', '|', '/'],
  interval: 120
};

export interface ProgressRenderOptions extends TerminalDetectionOptions {
  stream?: NodeJS.WriteStream & { isTTY?: boolean; columns?: number };
}

/**
 * Format helper for counts: "completed/total" or "completed" if total is unknown.
 * Never invents percentages when totals are unknown.
 */
export function formatCounts(completed?: number, total?: number): string {
  if (completed === undefined) {
    return '';
  }
  if (total !== undefined && total > 0) {
    return `${completed}/${total}`;
  }
  return `${completed}`;
}

/**
 * Encapsulates safe terminal line rendering:
 * - In animated TTY: handles spinner frame ticking and in-place line clearing without flicker.
 * - In CI / non-TTY / no-animation: prints discrete deterministic log lines on significant status changes.
 */
export class TerminalPresenter {
  private readonly stream: NodeJS.WriteStream;
  private readonly canAnimate: boolean;
  private readonly useColor: boolean;
  private readonly unicodeSupported: boolean;

  private frameIndex = 0;
  private timer: NodeJS.Timeout | null = null;
  private activeMessage = '';
  private lastPrintedNonInteractive = '';
  private isLineActive = false;

  constructor(options: ProgressRenderOptions = {}) {
    this.stream = (options.stream ?? process.stderr) as NodeJS.WriteStream;
    this.canAnimate = shouldAnimate(options);
    this.useColor = shouldUseColor(options);
    // On Windows with dumb terminal or without unicode, fallback to ascii symbols
    this.unicodeSupported = process.platform !== 'win32' || Boolean(process.env.WT_SESSION || process.env.TERM_PROGRAM);
  }

  public getSymbols(): typeof TERMINAL_SYMBOLS | typeof ASCII_TERMINAL_SYMBOLS {
    return this.unicodeSupported ? TERMINAL_SYMBOLS : ASCII_TERMINAL_SYMBOLS;
  }

  public getSpinnerFrame(): string {
    const frameSet = this.unicodeSupported ? SPINNER_FRAMES_UNICODE : SPINNER_FRAMES_ASCII;
    const frame = frameSet.frames[this.frameIndex % frameSet.frames.length] ?? frameSet.frames[0]!;
    return this.useColor ? chalk.cyan(frame) : frame;
  }

  /**
   * Starts periodic animation timer if terminal supports animation.
   */
  public start(onTick?: () => void): void {
    if (!this.canAnimate || this.timer) return;

    // Hide cursor during interactive animation
    if (this.stream.isTTY) {
      try {
        this.stream.write('\u001B[?25l');
      } catch {
        // ignore
      }
    }

    const interval = this.unicodeSupported ? SPINNER_FRAMES_UNICODE.interval : SPINNER_FRAMES_ASCII.interval;
    this.timer = setInterval(() => {
      this.frameIndex++;
      if (onTick) {
        onTick();
      } else if (this.activeMessage) {
        this.renderInteractive(this.activeMessage);
      }
    }, interval);
    this.timer.unref?.();
  }

  /**
   * Stops animation timer and restores cursor.
   */
  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.isLineActive && this.canAnimate) {
      this.clearLine();
    }
    // Restore cursor visibility
    if (this.canAnimate && this.stream.isTTY) {
      try {
        this.stream.write('\u001B[?25h');
      } catch {
        // ignore
      }
    }
    this.isLineActive = false;
  }

  /**
   * Updates current dynamic line.
   */
  public updateLine(message: string): void {
    this.activeMessage = message;
    if (this.canAnimate) {
      this.renderInteractive(message);
    } else {
      // In CI/non-interactive, only log if the text has changed meaningfully
      if (message && message !== this.lastPrintedNonInteractive) {
        this.lastPrintedNonInteractive = message;
        this.stream.write(`${message}\n`);
      }
    }
  }

  /**
   * Commits a completed, static message line (e.g. checkmark or final scanner outcome).
   */
  public logPermanent(message: string): void {
    if (this.canAnimate && this.isLineActive) {
      this.clearLine();
    }
    this.stream.write(`${message}\n`);
    this.isLineActive = false;
    this.activeMessage = '';
  }

  private renderInteractive(message: string): void {
    if (!this.stream.isTTY) {
      this.stream.write(`${message}\n`);
      return;
    }

    try {
      // Cursor to column 0 and clear line
      this.stream.cursorTo?.(0);
      this.stream.clearLine?.(0);
      const spinner = this.getSpinnerFrame();
      this.stream.write(`${spinner} ${message}`);
      this.isLineActive = true;
    } catch {
      // Fallback if cursor manipulation fails
      this.stream.write(`${message}\n`);
    }
  }

  private clearLine(): void {
    try {
      this.stream.cursorTo?.(0);
      this.stream.clearLine?.(0);
    } catch {
      // ignore
    }
  }
}

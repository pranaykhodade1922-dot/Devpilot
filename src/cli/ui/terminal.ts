/**
 * Robust ANSI escape code stripping regex matching SGR, cursor, and command sequences.
 */
const ANSI_REGEX =
  /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;

/**
 * Strips all ANSI escape sequences from a string.
 */
export function stripAnsi(text: string): string {
  return text.replace(ANSI_REGEX, '');
}

export interface TerminalDetectionOptions {
  stream?: { isTTY?: boolean; columns?: number };
  env?: NodeJS.ProcessEnv;
  argv?: string[];
}

/**
 * Determines whether the current stdout stream is an interactive TTY.
 */
export function isTTY(options?: TerminalDetectionOptions): boolean {
  if (options?.stream?.isTTY !== undefined) {
    return options.stream.isTTY;
  }
  return Boolean(process.stdout?.isTTY);
}

/**
 * Detects whether execution is occurring inside a continuous integration environment.
 */
export function isCI(options?: TerminalDetectionOptions): boolean {
  const env = options?.env ?? process.env;
  return Boolean(
    env.CI ||
      env.CONTINUOUS_INTEGRATION ||
      env.BUILD_NUMBER ||
      env.GITHUB_ACTIONS ||
      env.GITLAB_CI ||
      env.TRAVIS ||
      env.CIRCLECI ||
      env.TEAMCITY_VERSION
  );
}

/**
 * Detects whether the terminal is configured as a "dumb" terminal without cursor capabilities.
 */
export function isDumbTerminal(options?: TerminalDetectionOptions): boolean {
  const env = options?.env ?? process.env;
  return env.TERM === 'dumb';
}

/**
 * Determines whether colored output should be disabled based on:
 * - NO_COLOR environment variable (de-facto standard)
 * - Explicit --no-color or --color=false CLI arguments
 * - TERM=dumb
 */
export function hasNoColor(options?: TerminalDetectionOptions): boolean {
  const env = options?.env ?? process.env;
  const argv = options?.argv ?? process.argv;

  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') {
    return true;
  }
  if (isDumbTerminal(options)) {
    return true;
  }
  if (argv && (argv.includes('--no-color') || argv.includes('--color=false'))) {
    return true;
  }
  return false;
}

/**
 * Determines whether animation or dynamic spinner updates should be disabled based on:
 * - NO_ANIMATION environment variable
 * - Explicit --no-animation CLI argument
 * - Non-TTY or CI environment
 */
export function hasNoAnimation(options?: TerminalDetectionOptions): boolean {
  const env = options?.env ?? process.env;
  const argv = options?.argv ?? process.argv;

  if (env.NO_ANIMATION !== undefined && env.NO_ANIMATION !== '') {
    return true;
  }
  if (argv && argv.includes('--no-animation')) {
    return true;
  }
  return false;
}

/**
 * Evaluates whether real-time dynamic terminal animations should be displayed.
 */
export function shouldAnimate(options?: TerminalDetectionOptions): boolean {
  if (hasNoAnimation(options)) {
    return false;
  }
  if (isCI(options)) {
    return false;
  }
  if (isDumbTerminal(options)) {
    return false;
  }
  return isTTY(options);
}

/**
 * Evaluates whether colors should be used in terminal formatting.
 */
export function shouldUseColor(options?: TerminalDetectionOptions): boolean {
  if (hasNoColor(options)) {
    return false;
  }
  return true;
}

/**
 * Retrieves the current terminal column width, defaulting to 80.
 */
export function getTerminalWidth(options?: TerminalDetectionOptions, defaultWidth = 80): number {
  const cols = options?.stream?.columns ?? process.stdout?.columns;
  if (typeof cols === 'number' && cols > 0) {
    return cols;
  }
  return defaultWidth;
}

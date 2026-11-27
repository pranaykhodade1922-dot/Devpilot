/**
 * Shannon entropy calculation module for string randomness measurement.
 *
 * Shannon entropy measures the information density / unpredictability of a string.
 * - Uniform repeated strings (e.g. "aaaaaaa") have an entropy close to 0.0.
 * - Natural English prose typically has an entropy between 2.5 and 3.5.
 * - High-entropy cryptographic tokens / random Base64/Hex strings typically exceed 4.2.
 */

/**
 * Calculates the Shannon entropy (in bits per symbol, base 2) of a given string.
 *
 * Formula: H(X) = - SUM( P(x) * log2(P(x)) )
 *
 * @param input String to analyze
 * @returns Entropy value between 0.0 (minimum randomness) and log2(alphabet_size) (maximum randomness)
 */
export function calculateShannonEntropy(input: string): number {
  if (!input || input.length === 0) {
    return 0.0;
  }

  const length = input.length;
  const frequencies = new Map<string, number>();

  for (let i = 0; i < length; i++) {
    const char = input.charAt(i);
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0.0;
  for (const count of frequencies.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  // Round to 4 decimal places to avoid floating point precision noise
  return Math.round(entropy * 10000) / 10000;
}

/**
 * Evaluates whether a string meets or exceeds a target entropy threshold.
 *
 * @param input String to evaluate
 * @param threshold Minimum entropy required (e.g., 3.8 for Hex, 4.2 for Base64)
 */
export function meetsEntropyThreshold(input: string, threshold: number): boolean {
  return calculateShannonEntropy(input) >= threshold;
}

/**
 * Character sets for common encoding types.
 */
export const CHARACTER_SETS = {
  HEX: /^[0-9a-fA-F]+$/,
  BASE64: /^[0-9a-zA-Z+/=_-]+$/,
  NUMERIC: /^[0-9]+$/
} as const;

/**
 * Common entropy threshold guidelines.
 *
 * Note: Entropy is a supporting signal and must never be treated as standalone proof of a secret.
 */
export const ENTROPY_THRESHOLDS = {
  /** Hexadecimal strings (0-9, a-f) have a theoretical maximum entropy of log2(16) = 4.0 */
  HEX: 3.0,
  /** Base64 strings have a theoretical maximum entropy of log2(64) = 6.0 */
  BASE64: 4.2,
  /** Generic ASCII passwords and alphanumeric keys */
  GENERIC_HIGH: 3.8
} as const;

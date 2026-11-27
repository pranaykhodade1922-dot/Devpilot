import { describe, it, expect } from 'vitest';
import {
  calculateShannonEntropy,
  meetsEntropyThreshold,
  ENTROPY_THRESHOLDS
} from '../../../src/scanners/secret/entropy.js';

describe('Shannon Entropy Calculator', () => {
  it('returns 0.0 for empty or zero-length strings', () => {
    expect(calculateShannonEntropy('')).toBe(0.0);
    // @ts-expect-error test undefined guard
    expect(calculateShannonEntropy(undefined)).toBe(0.0);
  });

  it('returns 0.0 for strings of repeated identical characters', () => {
    expect(calculateShannonEntropy('aaaaaaa')).toBe(0.0);
    expect(calculateShannonEntropy('0000000000')).toBe(0.0);
    expect(calculateShannonEntropy('XXXXXXXX')).toBe(0.0);
  });

  it('calculates expected entropy for standard two-state strings', () => {
    // 50% 'a', 50% 'b' -> exactly 1.0 bit
    expect(calculateShannonEntropy('abababab')).toBe(1.0);
    expect(calculateShannonEntropy('aabb')).toBe(1.0);
  });

  it('produces lower entropy for natural language and predictable words', () => {
    const passwordEntropy = calculateShannonEntropy('password');
    const adminEntropy = calculateShannonEntropy('administrator');
    const exampleEntropy = calculateShannonEntropy('example_secret');

    expect(passwordEntropy).toBeLessThan(3.2);
    expect(adminEntropy).toBeLessThan(3.5);
    expect(exampleEntropy).toBeLessThan(3.6);
  });

  it('produces high entropy for random base64, hex, and cryptographic tokens', () => {
    // Synthetic random-like strings
    const randomHex = '4a8f9c1b2e3d7056e4a2b9f8c1d3e5a7'; // 32 hex chars
    const randomBase64 = 'k9Z#mP2$vL8*xQ1!wN4@bT7^yR3%uJ6&'; // 32 diverse chars
    const highEntropyKey = 'dGhpc19pc19hX3N5bnRoZXRpY190ZXN0X3NlY3JldF8xMjM0NTY=';

    expect(calculateShannonEntropy(randomHex)).toBeGreaterThanOrEqual(3.5);
    expect(calculateShannonEntropy(randomBase64)).toBeGreaterThanOrEqual(4.5);
    expect(calculateShannonEntropy(highEntropyKey)).toBeGreaterThanOrEqual(4.0);
  });

  it('meetsEntropyThreshold correctly identifies above/below threshold cases', () => {
    expect(meetsEntropyThreshold('00000000', ENTROPY_THRESHOLDS.HEX)).toBe(false);
    expect(meetsEntropyThreshold('password123', ENTROPY_THRESHOLDS.GENERIC_HIGH)).toBe(false);

    // High entropy synthetic key
    const syntheticToken = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    expect(meetsEntropyThreshold(syntheticToken, ENTROPY_THRESHOLDS.BASE64)).toBe(true);
  });
});

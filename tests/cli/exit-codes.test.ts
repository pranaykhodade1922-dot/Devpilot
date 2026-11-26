import { describe, it, expect } from 'vitest';
import {
  determineExitCode,
  CLI_EXIT_CODES
} from '../../src/cli/commands/security.js';
import type { DependencyScanSummary } from '../../src/scanners/dependency/types.js';

describe('CLI Exit Codes', () => {
  const baseSummary: DependencyScanSummary = {
    totalDependencies: 10,
    uniquePackages: 8,
    directCount: 2,
    transitiveCount: 8,
    vulnerableDependencies: 0,
    findingsCount: 0,
    severityCounts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
    scanStatus: 'CLEAN',
    durationMs: 120
  };

  it('returns Exit Code 0 (CLEAN) when scan completes with no vulnerabilities', () => {
    const summary: DependencyScanSummary = {
      ...baseSummary,
      scanStatus: 'CLEAN'
    };
    expect(determineExitCode(summary)).toBe(CLI_EXIT_CODES.CLEAN);
    expect(determineExitCode(summary)).toBe(0);
  });

  it('returns Exit Code 1 (VULNERABLE) when scan finds vulnerabilities', () => {
    const summary: DependencyScanSummary = {
      ...baseSummary,
      scanStatus: 'VULNERABLE',
      vulnerableDependencies: 1,
      findingsCount: 1
    };
    expect(determineExitCode(summary)).toBe(CLI_EXIT_CODES.VULNERABLE);
    expect(determineExitCode(summary)).toBe(1);
  });

  it('returns Exit Code 2 (FAILED) when scan encounters an error', () => {
    const summary: DependencyScanSummary = {
      ...baseSummary,
      scanStatus: 'FAILED',
      errorMessage: 'Lockfile not found'
    };
    expect(determineExitCode(summary)).toBe(CLI_EXIT_CODES.FAILED);
    expect(determineExitCode(summary)).toBe(2);
  });

  it('returns Exit Code 3 (PARTIAL) when scan completes partially with missing advisories', () => {
    const summary: DependencyScanSummary = {
      ...baseSummary,
      scanStatus: 'PARTIAL',
      hasIncompleteAdvisories: true
    };
    expect(determineExitCode(summary)).toBe(CLI_EXIT_CODES.PARTIAL);
    expect(determineExitCode(summary)).toBe(3);
  });
});

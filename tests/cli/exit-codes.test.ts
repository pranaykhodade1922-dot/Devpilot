import { describe, it, expect } from 'vitest';
import {
  determineExitCode,
  determineSecretExitCode,
  CLI_EXIT_CODES
} from '../../src/cli/commands/security.js';
import type { DependencyScanSummary } from '../../src/scanners/dependency/types.js';
import type { SecretScanSummary } from '../../src/scanners/secret/types.js';

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

  describe('Secret Scan Exit Codes', () => {
    const baseSecretSummary: SecretScanSummary = {
      totalFilesScanned: 5,
      totalLinesScanned: 100,
      findingsCount: 0,
      severityCounts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
      scanStatus: 'CLEAN',
      skippedFiles: [],
      errorSkippedCount: 0,
      intentionalSkippedCount: 0,
      durationMs: 50
    };

    it('returns Exit Code 0 (CLEAN) when secret scan has no findings', () => {
      const summary: SecretScanSummary = {
        ...baseSecretSummary,
        scanStatus: 'CLEAN'
      };
      expect(determineSecretExitCode(summary)).toBe(CLI_EXIT_CODES.CLEAN);
      expect(determineSecretExitCode(summary)).toBe(0);
    });

    it('returns Exit Code 1 (VULNERABLE) when secret scan detects secrets', () => {
      const summary: SecretScanSummary = {
        ...baseSecretSummary,
        scanStatus: 'VULNERABLE',
        findingsCount: 1,
        severityCounts: { CRITICAL: 1, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 }
      };
      expect(determineSecretExitCode(summary)).toBe(CLI_EXIT_CODES.VULNERABLE);
      expect(determineSecretExitCode(summary)).toBe(1);
    });

    it('returns Exit Code 2 (FAILED) when secret scan fails fatally', () => {
      const summary: SecretScanSummary = {
        ...baseSecretSummary,
        scanStatus: 'FAILED',
        errorMessage: 'Target path does not exist'
      };
      expect(determineSecretExitCode(summary)).toBe(CLI_EXIT_CODES.FAILED);
      expect(determineSecretExitCode(summary)).toBe(2);
    });

    it('returns Exit Code 3 (PARTIAL) when secret scan has unreadable or oversized files', () => {
      const summary: SecretScanSummary = {
        ...baseSecretSummary,
        scanStatus: 'PARTIAL',
        errorSkippedCount: 2
      };
      expect(determineSecretExitCode(summary)).toBe(CLI_EXIT_CODES.PARTIAL);
      expect(determineSecretExitCode(summary)).toBe(3);
    });
  });
});

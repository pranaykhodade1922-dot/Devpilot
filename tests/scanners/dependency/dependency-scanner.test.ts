import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  scanDependencies,
  normalizeSeverity,
  extractFixedVersions,
  computeRemediation,
  createSecurityFinding,
  deduplicateFindings
} from '../../../src/scanners/dependency/dependency-scanner.js';
import type {
  InstalledDependency,
  OsvBatchResponse,
  OsvVulnerability
} from '../../../src/scanners/dependency/types.js';

describe('Dependency Scanner', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-scanner-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows
    }
  });

  describe('normalizeSeverity', () => {
    it('evaluates CVSS 3.1 vector string correctly into CRITICAL', () => {
      const vuln: OsvVulnerability = {
        id: 'VULN-CVSS-VEC',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }]
      };
      const result = normalizeSeverity(vuln);
      expect(result.severity).toBe('CRITICAL');
      expect(result.cvssScore).toBe('9.8');
      expect(result.cvssVector).toContain('CVSS:3.1');
    });

    it('evaluates database_specific.severity correctly', () => {
      const vulnHigh: OsvVulnerability = {
        id: 'VULN-HIGH',
        database_specific: { severity: 'HIGH' }
      };
      expect(normalizeSeverity(vulnHigh).severity).toBe('HIGH');
    });

    it('returns UNKNOWN without inventing a rating when indeterminate', () => {
      const vuln: OsvVulnerability = { id: 'VULN-UNKNOWN' };
      expect(normalizeSeverity(vuln).severity).toBe('UNKNOWN');
    });
  });

  describe('computeRemediation', () => {
    it('recommends patch update within same major version when available', () => {
      const result = computeRemediation('my-lib', '1.2.0', ['1.2.5', '2.0.0']);
      expect(result.recommendation).toContain('1.2.5');
      expect(result.recommendation).toContain('within current major v1');
      expect(result.details.safeInCurrentMajor).toBe(true);
      expect(result.details.requiresMajorUpgrade).toBe(false);
    });

    it('notes major upgrade requirement when fix is only in higher major', () => {
      const result = computeRemediation('my-lib', '1.2.0', ['2.0.1', '3.0.0']);
      expect(result.recommendation).toContain('2.0.1');
      expect(result.recommendation).toContain('Requires major version upgrade');
      expect(result.details.requiresMajorUpgrade).toBe(true);
    });

    it('handles zero fixed versions safely', () => {
      const result = computeRemediation('my-lib', '1.0.0', []);
      expect(result.recommendation).toContain('No fixed version currently available');
    });
  });

  describe('deduplicateFindings', () => {
    it('deduplicates findings with shared aliases for the same package instance', () => {
      const dep: InstalledDependency = {
        name: 'lodash',
        version: '4.17.20',
        path: 'node_modules/lodash',
        isDirect: true
      };

      const vuln1: OsvVulnerability = {
        id: 'GHSA-35jh-r3h4-6jhm',
        aliases: ['CVE-2021-23337'],
        summary: 'Advisory 1',
        database_specific: { severity: 'HIGH' }
      };

      const vuln2: OsvVulnerability = {
        id: 'CVE-2021-23337',
        aliases: ['GHSA-35jh-r3h4-6jhm'],
        summary: 'Advisory 2',
        database_specific: { severity: 'CRITICAL' }
      };

      const finding1 = createSecurityFinding(dep, vuln1);
      const finding2 = createSecurityFinding(dep, vuln2);

      const deduped = deduplicateFindings([finding1, finding2]);
      expect(deduped).toHaveLength(1);
      expect(deduped[0]?.vulnerabilityId).toBe('CVE-2021-23337');
      expect(deduped[0]?.aliases).toContain('GHSA-35jh-r3h4-6jhm');
      expect(deduped[0]?.severity).toBe('CRITICAL');
    });
  });

  describe('scanDependencies end-to-end with Semver Validation & Hydration', () => {
    it('filters out unaffected versions using semver range matching (zero false positives)', async () => {
      const lockContent = {
        name: 'test-filter-app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { 'safe-patched-lib': '^2.5.0' } },
          'node_modules/safe-patched-lib': {
            version: '2.5.0'
          }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      // OSV returns a vulnerability candidate for the package
      const batchResponse: OsvBatchResponse = {
        results: [{ vulns: [{ id: 'GHSA-RANGE-TEST' }] }]
      };

      // Full advisory specifies vulnerable range [1.0.0, 2.0.0)
      const fullAdvisory: OsvVulnerability = {
        id: 'GHSA-RANGE-TEST',
        summary: 'Old vulnerability in safe-patched-lib',
        affected: [
          {
            package: { name: 'safe-patched-lib', ecosystem: 'npm' },
            ranges: [
              {
                type: 'SEMVER',
                events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }]
              }
            ]
          }
        ]
      };

      const mockFetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes('/querybatch')) {
          return { ok: true, status: 200, json: async () => batchResponse };
        }
        if (url.includes('/vulns/GHSA-RANGE-TEST')) {
          return { ok: true, status: 200, json: async () => fullAdvisory };
        }
        return { ok: false, status: 404 };
      });

      const result = await scanDependencies({
        cwd: tempDir,
        fetchFn: mockFetch as unknown as typeof fetch
      });

      // 2.5.0 is >= 2.0.0 (fixed), so it is verified as unaffected!
      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.findings).toHaveLength(0);
    });

    it('does not send workspace or local file packages to OSV query', async () => {
      const lockContent = {
        name: 'monorepo-app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { 'internal-pkg': 'file:packages/internal-pkg' } },
          'packages/internal-pkg': { version: '1.0.0' },
          'node_modules/internal-pkg': { link: true, resolved: 'packages/internal-pkg' }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const mockFetch = vi.fn();

      const result = await scanDependencies({
        cwd: tempDir,
        fetchFn: mockFetch as unknown as typeof fetch
      });

      // Local package excluded -> zero outbound OSV queries
      expect(mockFetch).not.toHaveBeenCalled();
      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.totalDependencies).toBe(0);
    });

    it('reports PARTIAL scan status when full advisory hydration fails', async () => {
      const lockContent = {
        name: 'partial-app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { 'some-pkg': '^1.0.0' } },
          'node_modules/some-pkg': { version: '1.0.0' }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const batchResponse: OsvBatchResponse = {
        results: [{ vulns: [{ id: 'GHSA-FAIL-HYDRATION' }] }]
      };

      const mockFetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes('/querybatch')) {
          return { ok: true, status: 200, json: async () => batchResponse };
        }
        // Advisory hydration fails with 500
        return { ok: false, status: 500, statusText: 'Server Error' };
      });

      const result = await scanDependencies({
        cwd: tempDir,
        fetchFn: mockFetch as unknown as typeof fetch
      });

      expect(result.summary.hasIncompleteAdvisories).toBe(true);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.isIncomplete).toBe(true);
    });

    it('retains indeterminate match instead of silently dropping vulnerability', async () => {
      const lockContent = {
        name: 'indeterminate-app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { 'indeterminate-pkg': '^1.0.0' } },
          'node_modules/indeterminate-pkg': { version: '1.0.0' }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const batchResponse: OsvBatchResponse = {
        results: [{ vulns: [{ id: 'GHSA-INDETERMINATE' }] }]
      };

      // Full advisory has empty ranges/versions so semver match cannot be determined
      const fullAdvisory: OsvVulnerability = {
        id: 'GHSA-INDETERMINATE',
        summary: 'Indeterminate advisory',
        affected: [
          {
            package: { name: 'indeterminate-pkg', ecosystem: 'npm' }
            // ranges and versions omitted
          }
        ]
      };

      const mockFetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes('/querybatch')) {
          return { ok: true, status: 200, json: async () => batchResponse };
        }
        if (url.includes('/vulns/GHSA-INDETERMINATE')) {
          return { ok: true, status: 200, json: async () => fullAdvisory };
        }
        return { ok: false, status: 404 };
      });

      const result = await scanDependencies({
        cwd: tempDir,
        fetchFn: mockFetch as unknown as typeof fetch
      });

      // Finding is retained and marked indeterminate with LOW confidence
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.isIndeterminate).toBe(true);
      expect(result.findings[0]?.confidence).toBe('LOW');
      expect(result.findings[0]?.title).toContain('[Indeterminate Match]');
    });
  });
});

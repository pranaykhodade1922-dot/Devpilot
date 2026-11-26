import { describe, it, expect, vi } from 'vitest';
import { OsvClient } from '../../../src/scanners/dependency/osv-client.js';
import type { OsvBatchResponse, OsvVulnerability } from '../../../src/scanners/dependency/types.js';

describe('OsvClient', () => {
  it('hydrates full advisory records from /v1/vulns/{id} after batch query', async () => {
    const batchResponse: OsvBatchResponse = {
      results: [
        {
          vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }]
        }
      ]
    };

    const fullAdvisory: OsvVulnerability = {
      id: 'GHSA-35jh-r3h4-6jhm',
      summary: 'Command Injection in lodash',
      details: 'Full details here',
      aliases: ['CVE-2021-23337'],
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }]
        }
      ]
    };

    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/querybatch')) {
        return {
          ok: true,
          status: 200,
          json: async () => batchResponse
        };
      }
      if (url.includes('/vulns/GHSA-35jh-r3h4-6jhm')) {
        return {
          ok: true,
          status: 200,
          json: async () => fullAdvisory
        };
      }
      return { ok: false, status: 404 };
    });

    const client = new OsvClient({ fetchFn: mockFetch as unknown as typeof fetch });
    const { resultsMap, hasIncompleteAdvisories } = await client.queryDependencies([
      { name: 'lodash', version: '4.17.20' }
    ]);

    expect(hasIncompleteAdvisories).toBe(false);
    const key = OsvClient.createQueryKey('lodash', '4.17.20');
    const vulns = resultsMap.get(key);
    expect(vulns).toHaveLength(1);
    expect(vulns?.[0]?.summary).toBe('Command Injection in lodash');
    expect(vulns?.[0]?.aliases).toContain('CVE-2021-23337');
    expect(vulns?.[0]?.affected?.[0]?.ranges?.[0]?.events?.[1]?.fixed).toBe('4.17.21');

    // Exactly 2 network calls: 1 querybatch + 1 advisory hydration
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('uses in-memory cache to prevent duplicate /v1/vulns/{id} requests', async () => {
    const batchResponse: OsvBatchResponse = {
      results: [
        { vulns: [{ id: 'GHSA-SHARED' }] },
        { vulns: [{ id: 'GHSA-SHARED' }] }
      ]
    };

    const fullAdvisory: OsvVulnerability = {
      id: 'GHSA-SHARED',
      summary: 'Shared advisory'
    };

    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/querybatch')) {
        return { ok: true, status: 200, json: async () => batchResponse };
      }
      if (url.includes('/vulns/GHSA-SHARED')) {
        return { ok: true, status: 200, json: async () => fullAdvisory };
      }
      return { ok: false, status: 404 };
    });

    const client = new OsvClient({ fetchFn: mockFetch as unknown as typeof fetch });
    await client.queryDependencies([
      { name: 'pkg-a', version: '1.0.0' },
      { name: 'pkg-b', version: '2.0.0' }
    ]);

    // querybatch called once, /vulns/GHSA-SHARED called once (cached for second hit!)
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(client.getCacheSize()).toBe(1);

    // Call again to verify cache persists across calls
    await client.queryDependencies([{ name: 'pkg-c', version: '3.0.0' }]);
    expect(client.getCacheSize()).toBe(1);
  });

  it('handles 404 on individual advisory hydration gracefully with incomplete flag', async () => {
    const batchResponse: OsvBatchResponse = {
      results: [{ vulns: [{ id: 'GHSA-MISSING-DETAILS' }] }]
    };

    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/querybatch')) {
        return { ok: true, status: 200, json: async () => batchResponse };
      }
      // Advisory endpoint returns 404
      return { ok: false, status: 404, statusText: 'Not Found' };
    });

    const client = new OsvClient({ fetchFn: mockFetch as unknown as typeof fetch });
    const { resultsMap, hasIncompleteAdvisories } = await client.queryDependencies([
      { name: 'pkg', version: '1.0.0' }
    ]);

    expect(hasIncompleteAdvisories).toBe(true);
    const key = OsvClient.createQueryKey('pkg', '1.0.0');
    const vulns = resultsMap.get(key);
    expect(vulns).toHaveLength(1);
    expect(vulns?.[0]?.id).toBe('GHSA-MISSING-DETAILS');
    expect(vulns?.[0]?.isIncomplete).toBe(true);
  });

  it('handles timeout during individual advisory hydration safely', async () => {
    const batchResponse: OsvBatchResponse = {
      results: [{ vulns: [{ id: 'GHSA-TIMEOUT' }] }]
    };

    const mockFetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/querybatch')) {
        return { ok: true, status: 200, json: async () => batchResponse };
      }
      const err = new Error('Timeout');
      err.name = 'TimeoutError';
      throw err;
    });

    const client = new OsvClient({ fetchFn: mockFetch as unknown as typeof fetch });
    const { resultsMap, hasIncompleteAdvisories } = await client.queryDependencies([
      { name: 'pkg', version: '1.0.0' }
    ]);

    expect(hasIncompleteAdvisories).toBe(true);
    const key = OsvClient.createQueryKey('pkg', '1.0.0');
    expect(resultsMap.get(key)?.[0]?.isIncomplete).toBe(true);
  });

  it('handles complete network failure on batch query by throwing formatted error', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    const client = new OsvClient({ fetchFn: mockFetch as unknown as typeof fetch });

    await expect(
      client.queryDependencies([{ name: 'pkg', version: '1.0.0' }])
    ).rejects.toThrow('Network failure while contacting OSV API');
  });
});

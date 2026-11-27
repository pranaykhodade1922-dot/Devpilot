import type {
  OsvBatchResponse,
  OsvPackageQuery,
  OsvVulnerability
} from './types.js';

export interface OsvClientOptions {
  baseUrl?: string;
  timeoutMs?: number;
  batchSize?: number;
  concurrency?: number;
  fetchFn?: typeof fetch;
}

export class OsvClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly batchSize: number;
  private readonly concurrency: number;
  private readonly fetchFn: typeof fetch;

  // In-memory cache for full advisory records across the entire scan session
  private readonly advisoryCache = new Map<string, OsvVulnerability>();

  constructor(options: OsvClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? 'https://api.osv.dev').replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? 15000;
    this.batchSize = options.batchSize ?? 100;
    this.concurrency = options.concurrency ?? 8;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
  }

  /**
   * Generates a stable deduplication key for package queries.
   */
  public static createQueryKey(packageName: string, version: string): string {
    return `${packageName.toLowerCase()}:::${version}`;
  }

  /**
   * Clears the in-memory advisory cache.
   */
  public clearCache(): void {
    this.advisoryCache.clear();
  }

  /**
   * Returns a copy of the advisory cache.
   */
  public getCacheSize(): number {
    return this.advisoryCache.size;
  }

  /**
   * Queries OSV for vulnerabilities across multiple package/version pairs.
   * Deduplicates queries, chunks into batches, hydrates full advisory details with caching
   * and bounded concurrency.
   */
  public async queryDependencies(
    dependencies: Array<{ name: string; version: string }>,
    progressHooks?: {
      onBatchProgress?: (params: {
        completedBatches: number;
        totalBatches: number;
        completedQueries: number;
        totalQueries: number;
      }) => void;
      onHydrateProgress?: (params: {
        completedAdvisories: number;
        totalAdvisories: number;
      }) => void;
    }
  ): Promise<{
    resultsMap: Map<string, OsvVulnerability[]>;
    hasIncompleteAdvisories: boolean;
  }> {
    const resultsMap = new Map<string, OsvVulnerability[]>();

    // 1. Deduplicate queries
    const uniqueQueriesMap = new Map<string, OsvPackageQuery>();
    for (const dep of dependencies) {
      const name = dep.name.trim();
      const version = dep.version.trim();
      if (!name || !version) {
        continue;
      }
      const key = OsvClient.createQueryKey(name, version);
      if (!uniqueQueriesMap.has(key)) {
        uniqueQueriesMap.set(key, {
          package: {
            name,
            ecosystem: 'npm'
          },
          version
        });
      }
    }

    const uniqueKeys = Array.from(uniqueQueriesMap.keys());
    const uniqueQueries = Array.from(uniqueQueriesMap.values());

    if (uniqueQueries.length === 0) {
      return { resultsMap, hasIncompleteAdvisories: false };
    }

    // 2. Execute batch queries to get candidate vulnerability stubs
    const rawStubsMap = new Map<string, OsvVulnerability[]>();
    const allVulnIdsToHydrate = new Set<string>();

    const totalBatches = Math.ceil(uniqueQueries.length / this.batchSize);
    let completedBatches = 0;
    let completedQueries = 0;

    for (let i = 0; i < uniqueQueries.length; i += this.batchSize) {
      const batchQueries = uniqueQueries.slice(i, i + this.batchSize);
      const batchKeys = uniqueKeys.slice(i, i + this.batchSize);

      const batchResults = await this.executeBatchQuery(batchQueries);

      for (let j = 0; j < batchQueries.length; j++) {
        const key = batchKeys[j];
        const resItem = batchResults.results[j];
        const vulns = resItem?.vulns ?? [];
        if (key) {
          rawStubsMap.set(key, vulns);
          for (const v of vulns) {
            if (v?.id) {
              allVulnIdsToHydrate.add(v.id);
            }
          }
        }
      }

      completedBatches++;
      completedQueries += batchQueries.length;

      try {
        progressHooks?.onBatchProgress?.({
          completedBatches,
          totalBatches,
          completedQueries,
          totalQueries: uniqueQueries.length
        });
      } catch {
        // Callback errors must never interrupt query execution
      }
    }

    // 3. Hydrate full advisory records for all candidate IDs with concurrency control
    const { hydratedMap, hasIncompleteAdvisories } = await this.hydrateAdvisories(
      Array.from(allVulnIdsToHydrate),
      progressHooks?.onHydrateProgress
    );

    // 4. Map hydrated full advisories back to package queries
    for (const [queryKey, stubs] of rawStubsMap.entries()) {
      const fullVulns: OsvVulnerability[] = [];
      for (const stub of stubs) {
        if (!stub?.id) continue;
        const full = hydratedMap.get(stub.id);
        if (full) {
          fullVulns.push(full);
        } else {
          // If hydration failed, preserve stub with incomplete marker
          fullVulns.push({
            ...stub,
            isIncomplete: true
          });
        }
      }
      resultsMap.set(queryKey, fullVulns);
    }

    return { resultsMap, hasIncompleteAdvisories };
  }

  /**
   * Retrieves a full advisory record by ID from GET /v1/vulns/{id}.
   * Uses in-memory cache and handles 404, timeouts and network failures independently.
   */
  public async getVulnerabilityById(id: string): Promise<OsvVulnerability | null> {
    if (!id || typeof id !== 'string') {
      return null;
    }

    const cleanId = id.trim();
    if (this.advisoryCache.has(cleanId)) {
      return this.advisoryCache.get(cleanId)!;
    }

    const endpoint = `${this.baseUrl}/v1/vulns/${encodeURIComponent(cleanId)}`;

    let response: Response;
    try {
      response = await this.fetchFn(endpoint, {
        method: 'GET',
        headers: {
          Accept: 'application/json'
        },
        signal: AbortSignal.timeout(this.timeoutMs)
      });
    } catch {
      // Independent timeout or network failure for single advisory
      return null;
    }

    if (!response.ok) {
      // 404 or non-200 status
      return null;
    }

    try {
      const data = (await response.json()) as OsvVulnerability;
      if (!data || typeof data !== 'object' || !data.id) {
        return null;
      }
      this.advisoryCache.set(cleanId, data);
      return data;
    } catch {
      return null;
    }
  }

  /**
   * Hydrates a set of vulnerability IDs into full advisory records with bounded concurrency.
   */
  private async hydrateAdvisories(
    ids: string[],
    onHydrateProgress?: (params: { completedAdvisories: number; totalAdvisories: number }) => void
  ): Promise<{ hydratedMap: Map<string, OsvVulnerability>; hasIncompleteAdvisories: boolean }> {
    const hydratedMap = new Map<string, OsvVulnerability>();
    let hasIncompleteAdvisories = false;

    if (ids.length === 0) {
      return { hydratedMap, hasIncompleteAdvisories: false };
    }

    // Process in bounded concurrency pools
    const poolLimit = Math.max(1, this.concurrency);
    const queue = [...ids];
    const totalAdvisories = ids.length;
    let completedAdvisories = 0;

    const worker = async () => {
      while (queue.length > 0) {
        const id = queue.shift();
        if (!id) break;

        const advisory = await this.getVulnerabilityById(id);
        if (advisory) {
          hydratedMap.set(id, advisory);
        } else {
          hasIncompleteAdvisories = true;
        }

        completedAdvisories++;
        try {
          onHydrateProgress?.({
            completedAdvisories,
            totalAdvisories
          });
        } catch {
          // Callback errors must never interrupt query execution
        }
      }
    };

    const workers = Array.from({ length: Math.min(poolLimit, ids.length) }, () => worker());
    await Promise.all(workers);

    return { hydratedMap, hasIncompleteAdvisories };
  }

  private async executeBatchQuery(queries: OsvPackageQuery[]): Promise<OsvBatchResponse> {
    const endpoint = `${this.baseUrl}/v1/querybatch`;

    let response: Response;
    try {
      response = await this.fetchFn(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(this.timeoutMs)
      });
    } catch (err: unknown) {
      if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
        throw new Error(`OSV API request timed out after ${this.timeoutMs}ms`);
      }
      throw new Error(
        `Network failure while contacting OSV API: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    if (!response.ok) {
      let errorBody = '';
      try {
        errorBody = await response.text();
      } catch {
        // ignore
      }
      throw new Error(
        `OSV API responded with HTTP ${response.status} (${response.statusText})${
          errorBody ? `: ${errorBody.slice(0, 200)}` : ''
        }`
      );
    }

    try {
      const json = (await response.json()) as OsvBatchResponse;
      if (!json || !Array.isArray(json.results)) {
        throw new Error('Invalid response structure received from OSV API');
      }
      return json;
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('Invalid response structure')) {
        throw err;
      }
      throw new Error(
        `Failed to parse OSV API JSON response: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
}

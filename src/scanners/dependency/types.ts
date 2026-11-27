import type { SecurityFinding, SeverityLevel } from '../../core/finding.js';

export interface InstalledDependency {
  name: string;
  version: string;
  path: string;
  isDirect: boolean;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  isWorkspace?: boolean;
  isOptional?: boolean;
  isBundled?: boolean;
}

export type LockfileErrorCode =
  | 'FILE_NOT_FOUND'
  | 'INVALID_JSON'
  | 'UNSUPPORTED_VERSION'
  | 'EMPTY_LOCKFILE';

export interface LockfileParseResult {
  success: boolean;
  lockfilePath: string;
  lockfileVersion?: number;
  dependencies: InstalledDependency[];
  directCount: number;
  transitiveCount: number;
  excludedWorkspaceCount: number;
  error?: string;
  errorCode?: LockfileErrorCode;
}

export interface OsvPackageQuery {
  package: {
    name: string;
    ecosystem: 'npm';
  };
  version: string;
}

export interface OsvVulnerabilityReference {
  type: string;
  url: string;
}

export interface OsvVulnerabilitySeverity {
  type: string;
  score: string;
}

export interface OsvAffectedEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvAffectedRange {
  type: string;
  events: OsvAffectedEvent[];
  repo?: string;
}

export interface OsvAffected {
  package?: {
    name: string;
    ecosystem: string;
  };
  ranges?: OsvAffectedRange[];
  versions?: string[];
  database_specific?: {
    severity?: string;
    cvss?: unknown;
    [key: string]: unknown;
  };
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  references?: OsvVulnerabilityReference[];
  severity?: OsvVulnerabilitySeverity[];
  affected?: OsvAffected[];
  database_specific?: {
    severity?: string;
    [key: string]: unknown;
  };
  isIncomplete?: boolean;
}

export interface OsvBatchResponseItem {
  vulns?: OsvVulnerability[];
}

export interface OsvBatchResponse {
  results: OsvBatchResponseItem[];
}

export type DependencyScanStatus = 'CLEAN' | 'VULNERABLE' | 'PARTIAL' | 'FAILED';

export type ScannerProgressStatus =
  | 'started'
  | 'progress'
  | 'completed'
  | 'failed'
  | 'skipped'
  | 'partial';

export type ScannerScanOutcome = 'clean' | 'vulnerable';

export type DependencyProgressStage =
  | 'discovery'
  | 'querying'
  | 'hydrating'
  | 'evaluating'
  | 'completed';

export interface DependencyProgressEvent {
  stage: DependencyProgressStage;
  status: ScannerProgressStatus;
  outcome?: ScannerScanOutcome;
  completed?: number;
  total?: number;
  message?: string;
  metadata?: {
    totalDependencies?: number;
    uniquePackages?: number;
    directCount?: number;
    transitiveCount?: number;
    batchesCompleted?: number;
    totalBatches?: number;
    queriesCompleted?: number;
    totalQueries?: number;
    advisoriesHydrated?: number;
    totalAdvisories?: number;
    vulnerableDependencies?: number;
    findingsCount?: number;
    durationMs?: number;
    errorMessage?: string;
  };
}

export interface DependencyScanSummary {
  totalDependencies: number;
  uniquePackages: number;
  directCount: number;
  transitiveCount: number;
  vulnerableDependencies: number;
  findingsCount: number;
  severityCounts: Record<SeverityLevel, number>;
  scanStatus: DependencyScanStatus;
  errorMessage?: string;
  hasIncompleteAdvisories?: boolean;
  durationMs: number;
}

export interface DependencyScanResult {
  summary: DependencyScanSummary;
  findings: SecurityFinding[];
  dependencies: InstalledDependency[];
}

export interface DependencyScanOptions {
  cwd?: string;
  lockfilePath?: string;
  osvBaseUrl?: string;
  timeoutMs?: number;
  batchSize?: number;
  concurrency?: number;
  fetchFn?: typeof fetch;
  onProgress?: (event: DependencyProgressEvent) => void;
}

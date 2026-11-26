export {
  parsePackageLock,
  extractPackageName
} from './lockfile-parser.js';

export {
  OsvClient,
  type OsvClientOptions
} from './osv-client.js';

export {
  scanDependencies,
  normalizeSeverity,
  extractFixedVersions,
  computeRemediation,
  createSecurityFinding,
  deduplicateFindings,
  type NormalizedSeverityResult
} from './dependency-scanner.js';

export {
  evaluateAffectedStatus,
  isVersionInEvents,
  normalizeSemver,
  type SemverMatchResult
} from './semver-matcher.js';

export {
  evaluateCvss,
  calculateCvss3BaseScore,
  scoreToSeverity,
  type CvssEvaluationResult
} from './cvss-helper.js';

export type {
  InstalledDependency,
  LockfileParseResult,
  LockfileErrorCode,
  DependencyScanOptions,
  DependencyScanResult,
  DependencyScanSummary,
  DependencyScanStatus,
  OsvVulnerability,
  OsvPackageQuery,
  OsvBatchResponse,
  OsvBatchResponseItem
} from './types.js';

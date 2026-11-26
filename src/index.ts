// Core public exports of DevPilot Security
export {
  detectProject,
  KNOWN_FRAMEWORKS,
  LOCKFILE_MAPPING,
  type ProjectInfo,
  type FrameworkSignature,
  type DetectProjectOptions
} from './core/project-detector.js';

export {
  type SecurityFinding,
  type SeverityLevel,
  type ConfidenceLevel,
  type DependencyType,
  type SeveritySource,
  type RemediationDetails,
  SEVERITY_ORDER
} from './core/finding.js';

export {
  parsePackageLock,
  extractPackageName,
  OsvClient,
  scanDependencies,
  normalizeSeverity,
  extractFixedVersions,
  computeRemediation,
  createSecurityFinding,
  deduplicateFindings,
  type NormalizedSeverityResult,
  evaluateAffectedStatus,
  isVersionInEvents,
  normalizeSemver,
  type SemverMatchResult,
  evaluateCvss,
  calculateCvss3BaseScore,
  scoreToSeverity,
  type CvssEvaluationResult,
  type InstalledDependency,
  type LockfileParseResult,
  type LockfileErrorCode,
  type DependencyScanOptions,
  type DependencyScanResult,
  type DependencyScanSummary,
  type DependencyScanStatus,
  type OsvVulnerability,
  type OsvPackageQuery,
  type OsvBatchResponse,
  type OsvBatchResponseItem,
  type OsvClientOptions
} from './scanners/dependency/index.js';

export { getDevPilotVersion, CLI_VERSION } from './utils/version.js';
export { getDoctorInfo, type DoctorResult } from './cli/commands/doctor.js';
export {
  runSecurityDeps,
  determineExitCode,
  CLI_EXIT_CODES,
  type CliExitCode,
  type SecurityDepsCommandOptions
} from './cli/commands/security.js';

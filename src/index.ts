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
  type SourceLocation,
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

export {
  getDevPilotVersion,
  getPackageMetadata,
  CLI_VERSION,
  type PackageMetadata
} from './utils/version.js';
export { getDoctorInfo, type DoctorResult } from './cli/commands/doctor.js';
export {
  getAboutInfo,
  formatAboutOutput,
  runAbout,
  type AboutInfo
} from './cli/commands/about.js';
export {
  runScan,
  determineUnifiedExitCode,
  type ScanCommandOptions,
  type UnifiedScanResult,
  type UnifiedScanSummary,
  type ScannerStatusSummary,
  type ScannerExecutionStatus
} from './cli/commands/scan.js';
export {
  runSecurityDeps,
  runSecuritySecrets,
  determineExitCode,
  determineSecretExitCode,
  CLI_EXIT_CODES,
  type CliExitCode,
  type SecurityDepsCommandOptions,
  type SecuritySecretsCommandOptions
} from './cli/commands/security.js';

export {
  scanSecrets,
  scanFileForSecrets,
  createSecretFinding,
  computeSecretScanStatus,
  BUILT_IN_RULES,
  evaluateLineRules,
  maskSecret,
  redactSecretFromLine,
  redactPrivateKeyBlocks,
  calculateShannonEntropy,
  crawlProjectFiles,
  type SecretCategory,
  type SkippedFileReason,
  type SkippedFileRecord,
  type SecretRule,
  type SecretMatchContext,
  type SecretMatch,
  type SecretScanStatus,
  type SecretScanSummary,
  type SecretScanResult,
  type SecretScanOptions,
  type FileCrawlerOptions,
  type CrawlResult
} from './scanners/secret/index.js';

export {
  scanSast,
  computeSastScanStatus,
  parseSourceCode,
  getScriptKindForPath,
  ImportTracker,
  ScopeTracker,
  analyzeSourceFile,
  BUILT_IN_SAST_RULES,
  RULE_SEC_SAST_EVAL,
  RULE_SEC_SAST_REACT_DANGEROUS_HTML,
  RULE_SEC_SAST_COMMAND_INJECTION,
  type SastRule,
  type SastRuleContext,
  type SastFindingCandidate,
  type SastScanOptions,
  type SastScanSummary,
  type SastScanResult,
  type SastScanStatus,
  type ParseResult,
  type ResolvedImport
} from './scanners/sast/index.js';

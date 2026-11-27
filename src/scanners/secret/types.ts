import type {
  ConfidenceLevel,
  SecurityFinding,
  SeverityLevel
} from '../../core/finding.js';

/**
 * Secret category classification.
 */
export type SecretCategory =
  | 'cloud'
  | 'api-key'
  | 'token'
  | 'private-key'
  | 'database'
  | 'password'
  | 'generic-entropy';

/**
 * Reason a file was skipped during crawling or scanning.
 */
export type SkippedFileReason =
  | 'EXCLUDED_DIRECTORY'
  | 'EXCLUDED_EXTENSION'
  | 'GITIGNORE_RULE'
  | 'TOO_LARGE'
  | 'BINARY_FILE'
  | 'PERMISSION_DENIED'
  | 'READ_ERROR'
  | 'PARSE_ERROR'
  | 'PARTIAL_ANALYSIS'
  | 'ENCODING_ERROR';

/**
 * Record of a file that was skipped intentionally or due to an error.
 */
export interface SkippedFileRecord {
  /** Relative or absolute file path */
  filePath: string;
  /** Reason classification */
  reason: SkippedFileReason;
  /** True if skipped intentionally by filter/policy; false if skipped due to an I/O or access error */
  isIntentionallyExcluded: boolean;
  /** Human-readable explanation or error message */
  details?: string;
}

/**
 * Declarative rule definition for detecting secrets.
 */
export interface SecretRule {
  /** Unique rule identifier (e.g., 'SEC-AWS-001', 'SEC-PK-001') */
  id: string;

  /** Human-readable rule name */
  name: string;

  /** Category of secret */
  category: SecretCategory;

  /** Standardized severity level */
  severity: SeverityLevel;

  /** Confidence level of the rule */
  confidence: ConfidenceLevel;

  /** Regular expression used to match the candidate secret */
  pattern: RegExp;

  /**
   * If pattern has capture groups, which group index contains the secret value?
   * Defaults to 0 (entire match) if not specified or out of bounds.
   */
  secretGroupIndex?: number;

  /** Optional minimum Shannon entropy threshold (0-8) required for a match */
  minEntropy?: number;

  /** Optional minimum character length required for the candidate secret */
  minLength?: number;

  /** Remediation guidance for this type of secret */
  remediation: string;

  /** Optional keywords to pre-filter lines before running regex for performance */
  keywords?: string[];

  /** Optional custom validator function to eliminate false positives */
  validate?: (match: SecretMatchContext) => boolean;
}

/**
 * Context provided to rule validators and filters.
 */
export interface SecretMatchContext {
  /** Raw candidate secret string (used only in transient memory during scan) */
  rawCandidate: string;
  /** Full line content */
  lineContent: string;
  /** 1-based line number */
  lineNumber: number;
  /** File path */
  filePath: string;
  /** Calculated Shannon entropy of the candidate */
  entropy: number;
  /** Optional array of all lines in the file being scanned for multiline context */
  allLines?: string[];
}

/**
 * Result of evaluating whether a candidate is a synthetic test fixture.
 */
export interface SyntheticFixtureResult {
  /** True if confirmed as an explicit synthetic test fixture */
  isSynthetic: boolean;
  /** Documented reason for classification */
  reason?: string;
}

/**
 * Secret match discovered in memory before redaction.
 */
export interface SecretMatch {
  rule: SecretRule;
  /** 1-based line number */
  lineNumber: number;
  /** 1-based column number where secret starts on the line */
  columnNumber: number;
  /** Calculated Shannon entropy */
  entropy: number;
  /** Start character index within the line */
  startOffset: number;
  /** End character index within the line (exclusive) */
  endOffset: number;
  /**
   * Safe masked representation of the secret.
   * NEVER the raw secret value.
   */
  maskedSecret: string;
  /**
   * Safe redacted line preview with secret replaced.
   * NEVER contains the raw secret value.
   */
  redactedLine: string;
}

/**
 * Scan status indicator for secret scanning.
 */
export type SecretScanStatus = 'CLEAN' | 'VULNERABLE' | 'PARTIAL' | 'FAILED';

export type SecretProgressStage = 'discovery' | 'scanning' | 'completed';

export interface SecretProgressEvent {
  stage: SecretProgressStage;
  status: 'started' | 'progress' | 'completed' | 'failed' | 'skipped' | 'partial';
  outcome?: 'clean' | 'vulnerable';
  completed?: number;
  total?: number;
  message?: string;
  metadata?: {
    currentFile?: string; // Relative path only, never absolute
    eligibleFilesCount?: number;
    processedFilesCount?: number;
    linesExamined?: number;
    findingsCount?: number;
    errorSkippedCount?: number;
    intentionalSkippedCount?: number;
    durationMs?: number;
    errorMessage?: string;
  };
}

/**
 * Summary metrics of a secret scan.
 */
export interface SecretScanSummary {
  /** Total number of files evaluated or crawled */
  totalFilesScanned: number;
  /** Total lines evaluated across all files */
  totalLinesScanned: number;
  /** Total number of secret findings */
  findingsCount: number;
  /** Breakdown by standardized severity level */
  severityCounts: Record<SeverityLevel, number>;
  /** Overall scan status */
  scanStatus: SecretScanStatus;
  /** List of files skipped (both intentionally and error-based) */
  skippedFiles: SkippedFileRecord[];
  /** Count of files skipped due to I/O, permission, or unreadable errors */
  errorSkippedCount: number;
  /** Count of files skipped intentionally (gitignore, extensions, dirs) */
  intentionalSkippedCount: number;
  /** Total scan duration in milliseconds */
  durationMs: number;
  /** Error message if scanStatus is FAILED */
  errorMessage?: string;
}

/**
 * Result returned by secret scanner.
 */
export interface SecretScanResult {
  summary: SecretScanSummary;
  findings: SecurityFinding[];
}

/**
 * Configuration options for secret scanning.
 */
export interface SecretScanOptions {
  /** Working directory or target path (defaults to process.cwd()) */
  cwd?: string;
  /** Maximum file size in bytes before skipping (defaults to 2MB) */
  maxFileSize?: number;
  /** Additional custom rules */
  customRules?: SecretRule[];
  /** Whether to respect .gitignore rules (defaults to true) */
  respectGitignore?: boolean;
  /** Optional callback for real-time progress events */
  onProgress?: (event: SecretProgressEvent) => void;
}

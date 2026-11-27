export {
  type SastRule,
  type SastRuleContext,
  type SastFindingCandidate,
  type SastScanOptions,
  type SastScanSummary,
  type SastScanResult,
  type SastScanStatus
} from './types.js';

export { parseSourceCode, getScriptKindForPath, type ParseResult } from './parser.js';
export { ImportTracker, type ResolvedImport } from './import-tracker.js';
export { ScopeTracker } from './scope-tracker.js';
export { analyzeSourceFile, type AnalyzeSourceOptions } from './analyzer.js';
export {
  scanSast,
  computeSastScanStatus,
  SAST_TARGET_EXTENSIONS
} from './sast-scanner.js';

export {
  BUILT_IN_SAST_RULES,
  RULE_SEC_SAST_EVAL,
  RULE_SEC_SAST_REACT_DANGEROUS_HTML,
  RULE_SEC_SAST_COMMAND_INJECTION
} from './rules/index.js';

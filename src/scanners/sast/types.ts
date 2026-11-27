import type ts from 'typescript';
import type { SecurityFinding, SeverityLevel, ConfidenceLevel } from '../../core/finding.js';
import type { SkippedFileRecord } from '../secret/types.js';

export type SastScanStatus = 'CLEAN' | 'VULNERABLE' | 'PARTIAL' | 'FAILED';

export interface SastFindingCandidate {
  node: ts.Node;
  severity?: SeverityLevel;
  confidence?: ConfidenceLevel;
  evidence?: string;
  notes?: string;
}

export interface SastRuleContext {
  node: ts.Node;
  sourceFile: ts.SourceFile;
  filePath: string;
  relPath: string;
  isShadowed: (identifier: string) => boolean;
  resolveImport: (identifierName: string) => { canonicalSource: string; exportedName: string } | undefined;
  isNamespaceImport: (identifierName: string) => string | undefined;
}

export interface SastRule {
  id: string;
  name: string;
  category: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  cwe: string[];
  owasp: string[];
  description: string;
  remediation: string;
  check: (ctx: SastRuleContext) => SastFindingCandidate[] | null;
}

export interface SastScanSummary {
  totalFilesScanned: number;
  totalLinesScanned: number;
  findingsCount: number;
  severityCounts: Record<SeverityLevel, number>;
  scanStatus: SastScanStatus;
  skippedFiles: SkippedFileRecord[];
  errorSkippedCount: number;
  intentionalSkippedCount: number;
  durationMs: number;
  hasSyntaxErrors?: boolean;
}

export interface SastScanResult {
  summary: SastScanSummary;
  findings: SecurityFinding[];
}

export interface SastScanOptions {
  cwd?: string;
  maxFileSize?: number;
  respectGitignore?: boolean;
  customRules?: SastRule[];
}

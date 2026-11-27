import ts from 'typescript';
import type { SecurityFinding } from '../../core/finding.js';
import type { SastRule, SastRuleContext } from './types.js';
import { ImportTracker } from './import-tracker.js';
import { ScopeTracker } from './scope-tracker.js';
import { BUILT_IN_SAST_RULES } from './rules/index.js';
import { redactSecretFromLine } from '../secret/masking.js';

export interface AnalyzeSourceOptions {
  filePath: string;
  relPath: string;
  sourceFile: ts.SourceFile;
  rules?: SastRule[];
}

/**
 * Traverses an AST and evaluates SAST rules against syntax nodes.
 */
export function analyzeSourceFile(options: AnalyzeSourceOptions): SecurityFinding[] {
  const { filePath, relPath, sourceFile, rules = BUILT_IN_SAST_RULES } = options;
  const findings: SecurityFinding[] = [];

  const importTracker = ImportTracker.fromSourceFile(sourceFile);
  const scopeTracker = new ScopeTracker();

  function visit(node: ts.Node): void {
    const isNewScope =
      ts.isBlock(node) ||
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isConstructorDeclaration(node) ||
      ts.isCatchClause(node) ||
      ts.isSourceFile(node);

    if (isNewScope && !ts.isSourceFile(node)) {
      scopeTracker.enterScope();
    }

    scopeTracker.registerDeclarations(node);

    const ruleContext: SastRuleContext = {
      node,
      sourceFile,
      filePath,
      relPath,
      isShadowed: (id: string) => scopeTracker.isShadowed(id),
      resolveImport: (id: string) => importTracker.resolveImport(id),
      isNamespaceImport: (id: string) => importTracker.isNamespaceImport(id)
    };

    // Evaluate all rules against this node
    for (const rule of rules) {
      const candidates = rule.check(ruleContext);
      if (candidates && candidates.length > 0) {
        for (const candidate of candidates) {
          const findingNode = candidate.node;
          const start = findingNode.getStart(sourceFile);
          const end = findingNode.getEnd();
          const startPos = sourceFile.getLineAndCharacterOfPosition(start);
          const endPos = sourceFile.getLineAndCharacterOfPosition(end);

          const lineNumber = startPos.line + 1;
          const columnNumber = startPos.character + 1;
          const endLineNumber = endPos.line + 1;
          const endColumnNumber = endPos.character + 1;

          // Evidence sanitization: ensure no raw credentials leak in snippet evidence
          const rawEvidence = candidate.evidence ?? findingNode.getText(sourceFile).trim();
          const sanitizedEvidence = redactSecretFromLine(rawEvidence, '');

          const finding: SecurityFinding = {
            id: `${rule.id}-${relPath}:${lineNumber}:${columnNumber}`,
            scanner: 'sast-scanner',
            packageName: relPath,
            installedVersion: `L${lineNumber}:C${columnNumber}`,
            vulnerabilityId: rule.id,
            ruleId: rule.id,
            aliases: [...rule.cwe, ...rule.owasp],
            cwe: rule.cwe,
            owasp: rule.owasp,
            title: `${rule.name} in ${relPath}`,
            description: candidate.notes
              ? `${rule.description} Notes: ${candidate.notes}`
              : rule.description,
            severity: candidate.severity ?? rule.severity,
            confidence: candidate.confidence ?? rule.confidence,
            evidence: sanitizedEvidence,
            remediation: rule.remediation,
            dependencyType: 'direct',
            location: {
              filePath: relPath,
              line: lineNumber,
              column: columnNumber,
              endLine: endLineNumber,
              endColumn: endColumnNumber
            },
            fixedVersions: [],
            references: []
          };

          findings.push(finding);
        }
      }
    }

    ts.forEachChild(node, visit);

    if (isNewScope && !ts.isSourceFile(node)) {
      scopeTracker.exitScope();
    }
  }

  visit(sourceFile);

  return findings;
}

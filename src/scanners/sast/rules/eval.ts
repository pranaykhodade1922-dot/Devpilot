import ts from 'typescript';
import type { SastRule, SastRuleContext, SastFindingCandidate } from '../types.js';
import { isStaticString, extractNodeSnippet } from './base.js';

function evaluateEvalCall(node: ts.CallExpression, sourceFile: ts.SourceFile): SastFindingCandidate {
  const firstArg = node.arguments[0];
  const isStatic = firstArg ? isStaticString(firstArg) : false;

  return {
    node,
    severity: isStatic ? 'MODERATE' : 'CRITICAL',
    confidence: 'HIGH',
    evidence: extractNodeSnippet(node, sourceFile),
    notes: isStatic
      ? 'eval() called with compile-time static string. Violates Content Security Policy (CSP).'
      : 'eval() called with dynamic expression. Potential arbitrary code execution.'
  };
}

export const RULE_SEC_SAST_EVAL: SastRule = {
  id: 'SEC-SAST-EVAL',
  name: 'Dynamic Code Execution via eval() or Function()',
  category: 'code-injection',
  severity: 'CRITICAL',
  confidence: 'HIGH',
  cwe: ['CWE-95', 'CWE-94'],
  owasp: ['A03:2021-Injection'],
  description:
    'Execution of code strings via eval() or the Function constructor can lead to arbitrary code execution if inputs are controlled by an attacker.',
  remediation:
    'Avoid eval() and the Function constructor entirely. Use JSON.parse() for serialized data, Web Workers for isolated execution, or native mapping dispatch tables.',
  check(ctx: SastRuleContext): SastFindingCandidate[] | null {
    const { node, sourceFile, isShadowed } = ctx;

    // 1. Direct or Global eval() Call
    if (ts.isCallExpression(node)) {
      const expr = node.expression;

      // 1a. Global eval(...) where 'eval' is not a property access and not lexically shadowed
      if (ts.isIdentifier(expr) && expr.text === 'eval') {
        if (isShadowed('eval')) {
          return null; // Shadowed locally, not the global eval
        }

        return [evaluateEvalCall(node, sourceFile)];
      }

      // 1b. window.eval(...) or globalThis.eval(...)
      if (ts.isPropertyAccessExpression(expr)) {
        const obj = expr.expression;
        const prop = expr.name;
        if (
          ts.isIdentifier(obj) &&
          (obj.text === 'window' || obj.text === 'globalThis' || obj.text === 'global') &&
          prop.text === 'eval'
        ) {
          return [evaluateEvalCall(node, sourceFile)];
        }
      }
    }

    // 2. Function constructor: new Function(...) or Function(...)
    if (ts.isNewExpression(node) || ts.isCallExpression(node)) {
      const expr = node.expression;
      if (ts.isIdentifier(expr) && expr.text === 'Function' && !isShadowed('Function')) {
        // Function() constructor requires at least 1 argument to evaluate dynamic code
        if (node.arguments && node.arguments.length > 0) {
          const lastArg = node.arguments[node.arguments.length - 1];
          const isStatic = lastArg ? isStaticString(lastArg) : false;

          return [
            {
              node,
              severity: isStatic ? 'MODERATE' : 'CRITICAL',
              confidence: 'HIGH',
              evidence: extractNodeSnippet(node, sourceFile),
              notes: isStatic
                ? 'Function constructor called with static string argument. Anti-pattern and CSP violation.'
                : 'Function constructor called with dynamic argument. High risk of arbitrary code execution.'
            }
          ];
        }
      }
    }

    return null;
  }
};

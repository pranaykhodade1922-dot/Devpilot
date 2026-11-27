import ts from 'typescript';
import type { SastRule, SastRuleContext, SastFindingCandidate } from '../types.js';
import { isStaticString, extractNodeSnippet } from './base.js';

function isVerifiedDomPurifyCall(
  expr: ts.Expression,
  resolveImport: SastRuleContext['resolveImport'],
  isNamespaceImport: SastRuleContext['isNamespaceImport']
): boolean {
  if (!ts.isCallExpression(expr)) {
    return false;
  }

  // Pattern 1: DOMPurify.sanitize(...)
  if (ts.isPropertyAccessExpression(expr.expression)) {
    const obj = expr.expression.expression;
    const prop = expr.expression.name;

    if (ts.isIdentifier(obj) && prop.text === 'sanitize') {
      const resolved = resolveImport(obj.text);
      if (
        resolved &&
        (resolved.canonicalSource === 'dompurify' ||
          resolved.canonicalSource === 'isomorphic-dompurify')
      ) {
        return true;
      }

      const ns = isNamespaceImport(obj.text);
      if (ns === 'dompurify' || ns === 'isomorphic-dompurify') {
        return true;
      }
    }
  }

  // Pattern 2: sanitize(...) where sanitize was imported from dompurify
  if (ts.isIdentifier(expr.expression)) {
    const resolved = resolveImport(expr.expression.text);
    if (
      resolved &&
      (resolved.canonicalSource === 'dompurify' ||
        resolved.canonicalSource === 'isomorphic-dompurify') &&
      resolved.exportedName === 'sanitize'
    ) {
      return true;
    }
  }

  return false;
}

export const RULE_SEC_SAST_INNERHTML: SastRule = {
  id: 'SEC-SAST-INNERHTML',
  name: 'Unsafe DOM HTML Injection (innerHTML / outerHTML / insertAdjacentHTML)',
  category: 'xss',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: ['CWE-79'],
  owasp: ['A03:2021-Injection'],
  description:
    'Directly assigning dynamic or unescaped HTML to DOM insertion sinks such as innerHTML, outerHTML, or insertAdjacentHTML can lead to Cross-Site Scripting (XSS) in browser environments.',
  remediation:
    'Use textContent, createElement(), or setHTMLUnsafe() with sanitization. If raw HTML insertion is required, sanitize the input using a verified HTML sanitizer such as DOMPurify.sanitize().',
  check(ctx: SastRuleContext): SastFindingCandidate[] | null {
    const { node, sourceFile, resolveImport, isNamespaceImport } = ctx;

    let targetValue: ts.Expression | undefined;
    let sinkName = '';

    // 1. Property assignment: element.innerHTML = value or element.outerHTML = value
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (ts.isPropertyAccessExpression(node.left)) {
        const propName = node.left.name.text;
        if (propName === 'innerHTML' || propName === 'outerHTML') {
          targetValue = node.right;
          sinkName = propName;
        }
      }
    }
    // 2. Method call: element.insertAdjacentHTML('beforeend', value)
    else if (ts.isCallExpression(node)) {
      if (ts.isPropertyAccessExpression(node.expression)) {
        const methodName = node.expression.name.text;
        if (methodName === 'insertAdjacentHTML' && node.arguments.length >= 2) {
          targetValue = node.arguments[1];
          sinkName = 'insertAdjacentHTML';
        }
      }
    }

    if (!targetValue || !sinkName) {
      return null;
    }

    // Suppress harmless DOM clearing: el.innerHTML = '' or ""
    if (ts.isStringLiteral(targetValue) && targetValue.text === '') {
      return null;
    }

    // Check if value is wrapped in verified DOMPurify call
    if (isVerifiedDomPurifyCall(targetValue, resolveImport, isNamespaceImport)) {
      return null;
    }

    // Compile-time static string literal
    if (isStaticString(targetValue)) {
      return [
        {
          node,
          severity: 'LOW',
          confidence: 'HIGH',
          evidence: extractNodeSnippet(node, sourceFile),
          notes: `${sinkName} assigned static string literal. Verify the necessity of raw HTML insertion.`
        }
      ];
    }

    // Dynamic unverified HTML injection
    return [
      {
        node,
        severity: 'HIGH',
        confidence: 'HIGH',
        evidence: extractNodeSnippet(node, sourceFile),
        notes: `Dynamic expression assigned to ${sinkName} without verified DOMPurify sanitization. High risk of XSS.`
      }
    ];
  }
};

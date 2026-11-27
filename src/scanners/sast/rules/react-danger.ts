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
        (resolved.canonicalSource === 'dompurify' || resolved.canonicalSource === 'isomorphic-dompurify')
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
      (resolved.canonicalSource === 'dompurify' || resolved.canonicalSource === 'isomorphic-dompurify') &&
      resolved.exportedName === 'sanitize'
    ) {
      return true;
    }
  }

  return false;
}

export const RULE_SEC_SAST_REACT_DANGEROUS_HTML: SastRule = {
  id: 'SEC-SAST-REACT-DANGEROUS-HTML',
  name: 'Unsafe HTML Injection via React dangerouslySetInnerHTML',
  category: 'xss',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: ['CWE-79'],
  owasp: ['A03:2021-Injection'],
  description:
    'Passing unsanitized or dynamic markup to React dangerouslySetInnerHTML bypasses built-in React XSS protections and can lead to Cross-Site Scripting (XSS).',
  remediation:
    'Render content as standard JSX expressions wherever possible. If raw HTML is required, sanitize the input using a verified HTML sanitizer such as DOMPurify.sanitize().',
  check(ctx: SastRuleContext): SastFindingCandidate[] | null {
    const { node, sourceFile, resolveImport, isNamespaceImport } = ctx;

    // Check JSX attributes: <div dangerouslySetInnerHTML={{ __html: ... }} />
    if (!ts.isJsxAttribute(node)) {
      return null;
    }

    const attributeName = ts.isIdentifier(node.name) ? node.name.text : node.name.name.text;
    if (attributeName !== 'dangerouslySetInnerHTML') {
      return null;
    }

    const initializer = node.initializer;
    if (!initializer || !ts.isJsxExpression(initializer) || !initializer.expression) {
      return null;
    }

    const expr = initializer.expression;
    if (!ts.isObjectLiteralExpression(expr)) {
      // Dynamic object passed: e.g. <div dangerouslySetInnerHTML={customObj} />
      return [
        {
          node,
          severity: 'HIGH',
          confidence: 'HIGH',
          evidence: extractNodeSnippet(node, sourceFile),
          notes: 'dangerouslySetInnerHTML passed an unverified dynamic object. Risk of XSS.'
        }
      ];
    }

    // Look for __html property
    for (const prop of expr.properties) {
      if (ts.isPropertyAssignment(prop)) {
        const propName = prop.name;
        const nameText = ts.isIdentifier(propName)
          ? propName.text
          : ts.isStringLiteral(propName)
            ? propName.text
            : null;

        if (nameText === '__html') {
          const value = prop.initializer;

          // 1. Check if value is wrapped in a verified DOMPurify call
          if (isVerifiedDomPurifyCall(value, resolveImport, isNamespaceImport)) {
            // Verified safe sanitizer output reaches __html -> Suppress finding
            return null;
          }

          // 2. Compile-time static string literal
          if (isStaticString(value)) {
            return [
              {
                node,
                severity: 'LOW',
                confidence: 'HIGH',
                evidence: extractNodeSnippet(node, sourceFile),
                notes: 'dangerouslySetInnerHTML assigned static string literal. Verify need for raw HTML.'
              }
            ];
          }

          // 3. Dynamic value without verified sanitizer
          return [
            {
              node,
              severity: 'HIGH',
              confidence: 'HIGH',
              evidence: extractNodeSnippet(node, sourceFile),
              notes:
                'dangerouslySetInnerHTML assigned dynamic expression without verified DOMPurify sanitization. High risk of XSS.'
            }
          ];
        }
      }
    }

    return null;
  }
};

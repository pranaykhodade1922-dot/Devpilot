import ts from 'typescript';
import type { SastRule, SastRuleContext, SastFindingCandidate } from '../types.js';
import { extractNodeSnippet } from './base.js';

const DEV_LOOPBACK_PATTERNS = [
  /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?(\/.*)?$/i,
  /^wss?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?(\/.*)?$/i,
  /^https?:\/\/([a-z0-9-]+\.)*(local|internal|test|localhost)(:\d+)?(\/.*)?$/i,
  /^https?:\/\/(www\.)?w3\.org\//i,
  /^https?:\/\/json-schema\.org\//i
];

function isSafeDevOrNamespaceUrl(url: string): boolean {
  return DEV_LOOPBACK_PATTERNS.some((pattern) => pattern.test(url));
}

function extractInsecurePrefix(expr: ts.Expression): string | null {
  // 1. Static string literal
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    const text = expr.text.trim();
    if ((text.startsWith('http://') || text.startsWith('ws://')) && !isSafeDevOrNamespaceUrl(text)) {
      return text;
    }
  }

  // 2. Template expression: `http://api.domain.com/${path}`
  if (ts.isTemplateExpression(expr)) {
    const head = expr.head.text.trim();
    if ((head.startsWith('http://') || head.startsWith('ws://')) && !isSafeDevOrNamespaceUrl(head)) {
      return head;
    }
  }

  // 3. Binary concatenation: 'http://api.domain.com/' + endpoint
  if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    if (ts.isStringLiteral(expr.left) || ts.isNoSubstitutionTemplateLiteral(expr.left)) {
      const text = expr.left.text.trim();
      if ((text.startsWith('http://') || text.startsWith('ws://')) && !isSafeDevOrNamespaceUrl(text)) {
        return text;
      }
    }
  }

  return null;
}

export const RULE_SEC_SAST_INSECURE_HTTP: SastRule = {
  id: 'SEC-SAST-INSECURE-HTTP',
  name: 'Insecure HTTP Network Request',
  category: 'network-security',
  severity: 'MODERATE',
  confidence: 'HIGH',
  cwe: ['CWE-319'],
  owasp: ['A02:2021-Cryptographic Failures'],
  description:
    'Potentially insecure cleartext network endpoint (unencrypted HTTP or WebSockets ws://) identified in source code. Transmitting data over unencrypted channels exposes traffic to interception or tampering if deployed to production.',
  remediation:
    'Use HTTPS (https://) or secure WebSockets (wss://) for all remote network endpoints. Limit unencrypted HTTP strictly to local development (localhost, 127.0.0.1) or test mock environments.',
  check(ctx: SastRuleContext): SastFindingCandidate[] | null {
    const { node, sourceFile } = ctx;

    let targetUrlExpr: ts.Expression | undefined;
    let sinkDescription = '';

    // 1. Direct function call: fetch(url), axios(url), got(url)
    if (ts.isCallExpression(node)) {
      const expr = node.expression;

      // fetch(url, ...)
      if (ts.isIdentifier(expr) && expr.text === 'fetch') {
        targetUrlExpr = node.arguments[0];
        sinkDescription = 'fetch()';
      }
      // axios(url) or got(url)
      else if (ts.isIdentifier(expr) && (expr.text === 'axios' || expr.text === 'got')) {
        targetUrlExpr = node.arguments[0];
        sinkDescription = `${expr.text}()`;
      }
      // Property access: axios.get(url), axios.post(url), http.get(url), http.request(url), xhr.open('GET', url)
      else if (ts.isPropertyAccessExpression(expr)) {
        const obj = expr.expression;
        const method = expr.name.text;

        if (ts.isIdentifier(obj)) {
          const objName = obj.text;

          // axios.get(url), axios.post(url), etc.
          if (
            (objName === 'axios' || objName === 'got' || objName === 'needle') &&
            ['get', 'post', 'put', 'patch', 'delete', 'head'].includes(method)
          ) {
            targetUrlExpr = node.arguments[0];
            sinkDescription = `${objName}.${method}()`;
          }
          // http.get(url), http.request(url)
          else if (
            (objName === 'http' || objName === 'https') &&
            (method === 'get' || method === 'request')
          ) {
            targetUrlExpr = node.arguments[0];
            sinkDescription = `${objName}.${method}()`;
          }
          // xhr.open(method, url)
          else if (
            (objName === 'xhr' || objName === 'req' || objName === 'xmlHttp') &&
            method === 'open' &&
            node.arguments.length >= 2
          ) {
            targetUrlExpr = node.arguments[1];
            sinkDescription = `${objName}.open()`;
          }
        }
      }
    }
    // 2. Constructor calls: new Request(url), new WebSocket(url)
    else if (ts.isNewExpression(node)) {
      const expr = node.expression;
      if (ts.isIdentifier(expr)) {
        if (expr.text === 'WebSocket' || expr.text === 'Request') {
          targetUrlExpr = node.arguments?.[0];
          sinkDescription = `new ${expr.text}()`;
        }
      }
    }

    if (!targetUrlExpr) {
      return null;
    }

    const insecurePrefix = extractInsecurePrefix(targetUrlExpr);
    if (!insecurePrefix) {
      return null;
    }

    const isWs = insecurePrefix.startsWith('ws://');
    const protocol = isWs ? 'unencrypted WebSocket (ws://)' : 'unencrypted HTTP (http://)';
    const recommendation = isWs ? 'wss://' : 'https://';

    return [
      {
        node,
        severity: 'MODERATE',
        confidence: 'HIGH',
        evidence: extractNodeSnippet(node, sourceFile),
        notes: `Potentially insecure source-code URL with ${protocol} identified in ${sinkDescription}. Replace with ${recommendation} unless this endpoint is strictly internal or an automated test mock.`
      }
    ];
  }
};

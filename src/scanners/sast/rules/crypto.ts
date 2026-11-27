import ts from 'typescript';
import type { SastRule, SastRuleContext, SastFindingCandidate } from '../types.js';
import { extractNodeSnippet } from './base.js';

const WEAK_HASH_ALGORITHMS = new Set([
  'md5',
  'md4',
  'md2',
  'sha1',
  'sha-1'
]);

const WEAK_CIPHER_PREFIXES = [
  'des',
  'rc4',
  'rc2',
  'blowfish',
  'idea'
];

const SECURITY_SENSITIVE_IDENTIFIER_REGEX =
  /(token|secret|password|passwd|auth|session|apikey|api_key|nonce|salt|credential)/i;

function isSecuritySensitiveContext(node: ts.Node): boolean {
  // Check parent nodes up to 8 levels (e.g. chaining .toString(36).substring(2))
  let current: ts.Node | undefined = node.parent;
  let depth = 0;

  while (current && depth < 8) {
    // 1. Variable declaration: const sessionToken = Math.random().toString(36)
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) {
      if (SECURITY_SENSITIVE_IDENTIFIER_REGEX.test(current.name.text)) {
        return true;
      }
    }
    // 2. Property assignment: { authToken: Math.random() }
    else if (ts.isPropertyAssignment(current)) {
      const propName = current.name;
      const text = ts.isIdentifier(propName)
        ? propName.text
        : ts.isStringLiteral(propName)
          ? propName.text
          : '';
      if (SECURITY_SENSITIVE_IDENTIFIER_REGEX.test(text)) {
        return true;
      }
    }
    // 3. Binary assignment: token = Math.random()
    else if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (ts.isIdentifier(current.left) && SECURITY_SENSITIVE_IDENTIFIER_REGEX.test(current.left.text)) {
        return true;
      }
    }
    // 4. Function declaration / method: function generateToken() { ... Math.random() ... }
    else if (
      (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) || ts.isMethodDeclaration(current)) &&
      current.name &&
      ts.isIdentifier(current.name)
    ) {
      if (SECURITY_SENSITIVE_IDENTIFIER_REGEX.test(current.name.text)) {
        return true;
      }
    }

    current = current.parent;
    depth++;
  }

  return false;
}

export const RULE_SEC_SAST_WEAK_CRYPTO: SastRule = {
  id: 'SEC-SAST-WEAK-CRYPTO',
  name: 'Use of Weak Cryptographic Algorithm or Insecure PRNG',
  category: 'cryptography',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: ['CWE-327', 'CWE-328', 'CWE-338'],
  owasp: ['A02:2021-Cryptographic Failures'],
  description:
    'Using broken or deprecated cryptographic algorithms (such as MD5, SHA-1, DES) or insecure pseudorandom number generators (Math.random) for security-sensitive tokens exposes applications to collision, forgery, or predictability attacks.',
  remediation:
    'Use strong cryptographic hash functions (SHA-256, SHA-3) or authenticated ciphers (AES-256-GCM). For passwords, use Argon2id, bcrypt, or scrypt. For security tokens and keys, use crypto.randomBytes() or crypto.randomUUID() instead of Math.random().',
  check(ctx: SastRuleContext): SastFindingCandidate[] | null {
    const { node, sourceFile, resolveImport } = ctx;

    if (!ts.isCallExpression(node)) {
      return null;
    }

    const expr = node.expression;

    // --- Scenario A: Insecure PRNG (Math.random()) in security-sensitive context ---
    if (ts.isPropertyAccessExpression(expr)) {
      const obj = expr.expression;
      const prop = expr.name;
      if (ts.isIdentifier(obj) && obj.text === 'Math' && prop.text === 'random') {
        if (isSecuritySensitiveContext(node)) {
          return [
            {
              node,
              severity: 'HIGH',
              confidence: 'HIGH',
              evidence: extractNodeSnippet(node, sourceFile),
              notes:
                'Math.random() used in security-sensitive credential/token context. Math.random() is cryptographically predictable. Use crypto.randomBytes() or crypto.randomUUID().'
            }
          ];
        }
        return null;
      }
    }

    // --- Scenario B: Obsolete crypto.createCipher() ---
    if (ts.isPropertyAccessExpression(expr)) {
      const prop = expr.name.text;
      const obj = expr.expression;
      if (prop === 'createCipher' && ts.isIdentifier(obj) && (obj.text === 'crypto' || resolveImport(obj.text)?.canonicalSource === 'crypto')) {
        return [
          {
            node,
            severity: 'HIGH',
            confidence: 'HIGH',
            evidence: extractNodeSnippet(node, sourceFile),
            notes:
              'crypto.createCipher() is deprecated and derives keys using weak MD5 hashing without salt. Use crypto.createCipheriv() with a securely generated key and IV.'
          }
        ];
      }
    }

    // --- Scenario C: Weak hash algorithm in crypto.createHash() or crypto.createHmac() ---
    let isHashOrHmac = false;
    let isCipherIv = false;

    if (ts.isPropertyAccessExpression(expr)) {
      const prop = expr.name.text;
      const obj = expr.expression;
      const isCryptoObj = ts.isIdentifier(obj) && (obj.text === 'crypto' || resolveImport(obj.text)?.canonicalSource === 'crypto');

      if (isCryptoObj) {
        if (prop === 'createHash' || prop === 'createHmac') {
          isHashOrHmac = true;
        } else if (prop === 'createCipheriv') {
          isCipherIv = true;
        }
      }
    } else if (ts.isIdentifier(expr)) {
      const resolved = resolveImport(expr.text);
      if (resolved && resolved.canonicalSource === 'crypto') {
        if (resolved.exportedName === 'createHash' || resolved.exportedName === 'createHmac') {
          isHashOrHmac = true;
        } else if (resolved.exportedName === 'createCipheriv') {
          isCipherIv = true;
        }
      }
    }

    // Check hash algorithms (MD5, SHA1, etc.)
    if (isHashOrHmac) {
      const firstArg = node.arguments[0];
      if (firstArg && (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg))) {
        const algo = firstArg.text.toLowerCase().trim();
        if (WEAK_HASH_ALGORITHMS.has(algo)) {
          return [
            {
              node,
              severity: 'MODERATE',
              confidence: 'HIGH',
              evidence: extractNodeSnippet(node, sourceFile),
              notes: `Cryptographic hash algorithm (${algo.toUpperCase()}) detected. If used for security purposes (integrity checks, signatures, or credentials), it is vulnerable to collision attacks. Use SHA-256, SHA-3, or Argon2id/bcrypt for passwords.`
            }
          ];
        }
      }
    }

    // Check cipher algorithms (DES, RC4, etc.)
    if (isCipherIv) {
      const firstArg = node.arguments[0];
      if (firstArg && (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg))) {
        const algo = firstArg.text.toLowerCase().trim();
        if (WEAK_CIPHER_PREFIXES.some((prefix) => algo.startsWith(prefix))) {
          return [
            {
              node,
              severity: 'HIGH',
              confidence: 'HIGH',
              evidence: extractNodeSnippet(node, sourceFile),
              notes: `Weak cipher algorithm (${algo}) detected. Vulnerable to known cryptographic attacks. Use AES-256-GCM or ChaCha20-Poly1305.`
            }
          ];
        }
      }
    }

    return null;
  }
};

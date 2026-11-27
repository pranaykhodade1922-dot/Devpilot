import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../../src/scanners/sast/parser.js';
import { analyzeSourceFile } from '../../../../src/scanners/sast/analyzer.js';
import { RULE_SEC_SAST_WEAK_CRYPTO } from '../../../../src/scanners/sast/rules/crypto.js';

describe('SAST Rule: SEC-SAST-WEAK-CRYPTO', () => {
  it('detects MD5 and SHA-1 in crypto.createHash() as MODERATE severity', () => {
    const code = `
      import crypto from 'crypto';
      function hashData(content: string) {
        const hashMd5 = crypto.createHash('md5').update(content).digest('hex');
        const hashSha1 = crypto.createHash('sha1').update(content).digest('hex');
        return { hashMd5, hashSha1 };
      }
    `;
    const { sourceFile } = parseSourceCode('src/hash.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/hash.ts',
      relPath: 'src/hash.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_WEAK_CRYPTO]
    });

    expect(findings.length).toBe(2);
    expect(findings[0]?.ruleId).toBe('SEC-SAST-WEAK-CRYPTO');
    expect(findings[0]?.severity).toBe('MODERATE');
    expect(findings[0]?.cwe).toContain('CWE-328');
    expect(findings[1]?.severity).toBe('MODERATE');
  });

  it('detects deprecated crypto.createCipher() as HIGH severity', () => {
    const code = `
      import crypto from 'crypto';
      function encryptSecret(key: string, data: string) {
        const cipher = crypto.createCipher('aes192', key);
        return cipher.update(data, 'utf8', 'hex');
      }
    `;
    const { sourceFile } = parseSourceCode('src/cipher.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/cipher.ts',
      relPath: 'src/cipher.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_WEAK_CRYPTO]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.cwe).toContain('CWE-327');
    expect(findings[0]?.evidence).toContain("crypto.createCipher('aes192', key)");
  });

  it('detects weak ciphers (e.g. DES) in crypto.createCipheriv() as HIGH severity', () => {
    const code = `
      import crypto from 'crypto';
      function runDes(key: Buffer, iv: Buffer) {
        return crypto.createCipheriv('des-ede', key, iv);
      }
    `;
    const { sourceFile } = parseSourceCode('src/des.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/des.ts',
      relPath: 'src/des.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_WEAK_CRYPTO]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.description).toContain('Weak cipher algorithm (des-ede) detected');
  });

  it('detects Math.random() in security-sensitive token/credential contexts as HIGH severity', () => {
    const code = `
      function createSession() {
        const sessionToken = Math.random().toString(36).substring(2);
        const apiKey = Math.random().toString(16);
        return { sessionToken, apiKey };
      }
    `;
    const { sourceFile } = parseSourceCode('src/token.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/token.ts',
      relPath: 'src/token.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_WEAK_CRYPTO]
    });

    expect(findings.length).toBe(2);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.confidence).toBe('HIGH');
    expect(findings[0]?.cwe).toContain('CWE-338');
    expect(findings[0]?.description).toContain('Math.random() used in security-sensitive credential/token context');
  });

  it('does NOT flag Math.random() in non-security mathematical / UI contexts', () => {
    const code = `
      function rollDie() {
        return Math.floor(Math.random() * 6) + 1;
      }
      function getJitter() {
        return Math.random() * 100;
      }
    `;
    const { sourceFile } = parseSourceCode('src/game.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/game.ts',
      relPath: 'src/game.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_WEAK_CRYPTO]
    });

    expect(findings.length).toBe(0);
  });

  it('does NOT flag strong cryptographic algorithms (SHA-256, AES-256-GCM)', () => {
    const code = `
      import crypto from 'crypto';
      function strongCrypto(key: Buffer, iv: Buffer, data: string) {
        const hash = crypto.createHash('sha256').update(data).digest('hex');
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const token = crypto.randomBytes(32).toString('hex');
        return { hash, cipher, token };
      }
    `;
    const { sourceFile } = parseSourceCode('src/strong.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/strong.ts',
      relPath: 'src/strong.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_WEAK_CRYPTO]
    });

    expect(findings.length).toBe(0);
  });
});

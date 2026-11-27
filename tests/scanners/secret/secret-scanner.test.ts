import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  scanSecrets,
  scanFileForSecrets,
  computeSecretScanStatus
} from '../../../src/scanners/secret/secret-scanner.js';

describe('Secret Scanner Orchestrator (secret-scanner.ts)', () => {
  let fixtureDir: string;

  beforeEach(() => {
    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-scanner-fixture-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  });

  describe('Exit Code Status Computation', () => {
    it('returns CLEAN (Exit Code 0) when 0 findings and 0 errors', () => {
      expect(computeSecretScanStatus(0, 0)).toBe('CLEAN');
    });

    it('returns VULNERABLE (Exit Code 1) when findings exist and 0 errors', () => {
      expect(computeSecretScanStatus(3, 0)).toBe('VULNERABLE');
    });

    it('returns PARTIAL (Exit Code 3) when errors/skips occurred during crawl', () => {
      expect(computeSecretScanStatus(0, 1)).toBe('PARTIAL');
      expect(computeSecretScanStatus(2, 1)).toBe('PARTIAL');
    });
  });

  describe('End-to-End Fixture Scanning', () => {
    it('returns CLEAN status on projects with clean source files', async () => {
      const srcDir = path.join(fixtureDir, 'src');
      fs.mkdirSync(srcDir, { recursive: true });
      fs.writeFileSync(
        path.join(srcDir, 'index.ts'),
        'export function add(a: number, b: number) { return a + b; }\n'
      );
      fs.writeFileSync(
        path.join(srcDir, 'utils.ts'),
        'export const GREETING = "Hello, world!";\n'
      );

      const result = await scanSecrets({ cwd: fixtureDir });

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.findingsCount).toBe(0);
      expect(result.findings.length).toBe(0);
      expect(result.summary.totalFilesScanned).toBe(2);
      expect(result.summary.totalLinesScanned).toBeGreaterThan(0);
    });

    it('detects and redacts multiple secrets in source files with accurate line numbers', async () => {
      const configDir = path.join(fixtureDir, 'config');
      fs.mkdirSync(configDir, { recursive: true });

      // File with synthetic secrets
      const configFile = path.join(configDir, 'settings.env');
      const lines = [
        '# Server configuration',
        'PORT=3000',
        'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"', // Line 3
        'APP_ENV="production"',
        'DATABASE_URL="postgres://admin:sUp3rS3cr3tP%40ss@db.internal:5432/app"', // Line 5
        'GITHUB_TOKEN="ghp_0123456789abcdefghijklmnopqrstuvwxyz"' // Line 6
      ];
      fs.writeFileSync(configFile, lines.join('\n'));

      const result = await scanSecrets({ cwd: fixtureDir });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.summary.findingsCount).toBe(3);
      expect(result.findings.length).toBe(3);

      // Verify line numbers
      const awsFinding = result.findings.find((f) => f.vulnerabilityId === 'SEC-AWS-001');
      expect(awsFinding).toBeDefined();
      expect(awsFinding?.installedVersion).toBe('L3:C20');
      expect(awsFinding?.packageName).toBe('config/settings.env');
      expect(awsFinding?.evidence).toContain('AWS_ACCESS_KEY_ID="AKI...[REDACTED]...PLE"');

      // Verify zero raw secret leakage
      expect(awsFinding?.evidence.includes('IOSFODNN7')).toBe(false);

      const dbFinding = result.findings.find((f) => f.vulnerabilityId === 'SEC-DB-001');
      expect(dbFinding).toBeDefined();
      expect(dbFinding?.installedVersion).toBe('L5:C32');
      expect(dbFinding?.evidence.includes('sUp3rS3cr3tP%40ss')).toBe(false);

      const ghFinding = result.findings.find((f) => f.vulnerabilityId === 'SEC-GH-001');
      expect(ghFinding).toBeDefined();
      expect(ghFinding?.installedVersion).toBe('L6:C15');
      expect(ghFinding?.evidence.includes('0123456789abcdef')).toBe(false);
    });

    it('completely redacts multiline private key blocks while preserving subsequent line numbers', async () => {
      const keysDir = path.join(fixtureDir, 'keys');
      fs.mkdirSync(keysDir, { recursive: true });

      const keyFile = path.join(keysDir, 'server.pem');
      const keyContent = [
        '# Line 1: Development Private Key',
        '-----BEGIN RSA PRIVATE KEY-----', // Line 2
        'MIIEowIBAAKCAQEA0Y9VzFakePayloadBody1234567890abcdef==', // Line 3
        'MIIBogIBAAKCAQEAzFakeMiddlePayloadRowTwo1234567890==', // Line 4
        '-----END RSA PRIVATE KEY-----', // Line 5
        '# Line 6: Comment',
        'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"' // Line 7
      ].join('\n');
      fs.writeFileSync(keyFile, keyContent);

      const result = await scanSecrets({ cwd: fixtureDir });

      expect(result.summary.findingsCount).toBe(2);

      const pkFinding = result.findings.find((f) => f.vulnerabilityId === 'SEC-PK-001');
      expect(pkFinding).toBeDefined();
      expect(pkFinding?.severity).toBe('CRITICAL');
      expect(pkFinding?.installedVersion).toBe('L2:C1');

      // Crucial regression check: Line 7 finding must preserve its exact original line number (L7), not L4 or L5
      const awsFinding = result.findings.find((f) => f.vulnerabilityId === 'SEC-AWS-001');
      expect(awsFinding).toBeDefined();
      expect(awsFinding?.installedVersion).toBe('L7:C20');

      // Crucial: body bytes must NOT appear anywhere in findings or evidence
      const findingStr = JSON.stringify(result.findings);
      expect(findingStr.includes('MIIEowIBAAKCAQEA0Y9VzFakePayloadBody')).toBe(false);
      expect(findingStr.includes('FakeMiddlePayloadRowTwo')).toBe(false);
    });

    it('safely handles incomplete private key blocks containing credential-like strings', async () => {
      const targetFile = path.join(fixtureDir, 'incomplete.pem');
      const keyContent = [
        '# Incomplete Key without END marker',
        '-----BEGIN RSA PRIVATE KEY-----', // Line 2
        'MIIEowIBAAKCAQEA0Y9VzFakePayloadBody1234567890abcdef==', // Line 3
        'AWS_SECRET="AKIAIOSFODNN7EXAMPLE"', // Line 4 (inside unclosed private key body)
        'more_raw_payload_bytes==' // Line 5
      ].join('\n');
      fs.writeFileSync(targetFile, keyContent);

      const result = await scanSecrets({ cwd: fixtureDir });

      // The unclosed private key is flagged once
      expect(result.summary.findingsCount).toBe(1);
      expect(result.findings[0]?.vulnerabilityId).toBe('SEC-PK-001');

      // Crucial: the payload lines (lines 3-5) were redacted to [REDACTED PRIVATE KEY LINE]
      // so the credential inside the private key body was NOT leaked or treated as raw code
      const findingStr = JSON.stringify(result.findings);
      expect(findingStr.includes('MIIEowIBAAKCAQEA0Y9VzFakePayloadBody')).toBe(false);
      expect(findingStr.includes('more_raw_payload_bytes')).toBe(false);
    });

    it('intentionally excludes binary files without triggering PARTIAL status', async () => {
      // 1 valid clean text file
      fs.writeFileSync(path.join(fixtureDir, 'clean.js'), 'console.log("hello");');

      // 1 binary file with null byte
      const binFile = path.join(fixtureDir, 'corrupt.dat');
      fs.writeFileSync(binFile, Buffer.from([0x01, 0x00, 0x02]));

      const result = await scanSecrets({ cwd: fixtureDir });

      // Binary files are intentionally excluded by policy -> scanStatus remains CLEAN (Exit Code 0)
      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.errorSkippedCount).toBe(0);
      expect(result.summary.intentionalSkippedCount).toBe(1);
      expect(result.summary.findingsCount).toBe(0);
    });

    it('returns PARTIAL status when eligible text files exceed maxFileSize', async () => {
      // 1 valid clean text file
      fs.writeFileSync(path.join(fixtureDir, 'clean.js'), 'console.log("hello");');

      // 1 oversized text file (> 100 bytes)
      fs.writeFileSync(path.join(fixtureDir, 'huge.txt'), 'A'.repeat(500));

      const result = await scanSecrets({ cwd: fixtureDir, maxFileSize: 100 });

      // Oversized eligible text files cannot be fully scanned -> scanStatus becomes PARTIAL (Exit Code 3)
      expect(result.summary.scanStatus).toBe('PARTIAL');
      expect(result.summary.errorSkippedCount).toBe(1);
      expect(result.summary.skippedFiles.some((s) => s.reason === 'TOO_LARGE')).toBe(true);
    });

    it('returns FAILED status on non-existent root path', async () => {
      const nonExistent = path.join(fixtureDir, 'no-such-path');
      const result = await scanSecrets({ cwd: nonExistent });

      expect(result.summary.scanStatus).toBe('FAILED');
      expect(result.summary.errorMessage).toBeDefined();
      expect(result.findings.length).toBe(0);
    });

    it('confirms scanned files are 100% read-only and never modified or deleted', async () => {
      const targetFile = path.join(fixtureDir, 'target.ts');
      const originalContent = 'const apiKey = "AKIAIOSFODNN7EXAMPLE";\n';
      fs.writeFileSync(targetFile, originalContent);

      await scanSecrets({ cwd: fixtureDir });

      // Check file was not altered in any way
      const contentAfter = fs.readFileSync(targetFile, 'utf8');
      expect(contentAfter).toBe(originalContent);
    });
  });
});

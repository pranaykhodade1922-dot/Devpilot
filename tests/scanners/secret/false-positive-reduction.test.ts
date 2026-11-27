import { describe, it, expect } from 'vitest';
import {
  evaluateLineRules,
  isIsolatedPemHeader,
  isSyntheticTestFixture,
  BUILT_IN_RULES
} from '../../../src/scanners/secret/rules.js';
import { redactPrivateKeyBlocks, maskSecret, redactSecretFromLine } from '../../../src/scanners/secret/masking.js';
import { scanFileForSecrets } from '../../../src/scanners/secret/secret-scanner.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('False-Positive Reduction & PEM Precision (Regression Suite)', () => {
  const testFilePath = 'tests/auth/login.test.ts';

  // --------------------------------------------------------------------------
  // Requirement 1: Explicit synthetic AWS fixture is recognized and suppressed
  // --------------------------------------------------------------------------
  it('1. Suppresses explicit canonical synthetic AWS fixture (AKIAIOSFODNN7EXAMPLE) in test files', () => {
    const syntheticLine = ['const sampleKey = "', 'AKIA', 'IOSFODNN7', 'EXAMPLE";'].join('');
    const matches = evaluateLineRules(syntheticLine, 1, testFilePath);

    expect(matches.length).toBe(0);

    const fixtureCheck = isSyntheticTestFixture({
      rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-AWS-001')!,
      rawCandidate: ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join(''),
      lineContent: syntheticLine,
      lineNumber: 1,
      columnNumber: 19,
      filePath: testFilePath
    });
    expect(fixtureCheck.isSynthetic).toBe(true);
    expect(fixtureCheck.reason).toBeDefined();
  });

  // --------------------------------------------------------------------------
  // Requirement 2: Realistic AWS credential in a test file is still detected
  // --------------------------------------------------------------------------
  it('2. Detects realistic AWS credential in a test file when no fixture markers exist', () => {
    const realisticAwsKey = ['AKIA', 'X5T8B4Q1M9K2L3R6'].join('');
    const line = `const activeKey = "${realisticAwsKey}";`;
    const matches = evaluateLineRules(line, 1, testFilePath);

    expect(matches.length).toBe(1);
    expect(matches[0]?.rule.id).toBe('SEC-AWS-001');
    expect(matches[0]?.rule.severity).toBe('CRITICAL');

    const fixtureCheck = isSyntheticTestFixture({
      rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-AWS-001')!,
      rawCandidate: realisticAwsKey,
      lineContent: line,
      lineNumber: 1,
      columnNumber: 19,
      filePath: testFilePath
    });
    expect(fixtureCheck.isSynthetic).toBe(false);
  });

  // --------------------------------------------------------------------------
  // Requirement 3: Synthetic GitLab token fixture is recognized and suppressed
  // --------------------------------------------------------------------------
  it('3. Suppresses synthetic sequential GitLab token fixture in test files', () => {
    const syntheticGitLabToken = ['glpat-', '0123456789abcdefghij'].join('');
    const line = `const dummyGl = "${syntheticGitLabToken}";`;
    const matches = evaluateLineRules(line, 1, testFilePath);

    expect(matches.length).toBe(0);

    const fixtureCheck = isSyntheticTestFixture({
      rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-GL-001')!,
      rawCandidate: syntheticGitLabToken,
      lineContent: line,
      lineNumber: 1,
      columnNumber: 17,
      filePath: testFilePath
    });
    expect(fixtureCheck.isSynthetic).toBe(true);
  });

  // --------------------------------------------------------------------------
  // Requirement 4: Realistic GitLab token in a test file is still detected
  // --------------------------------------------------------------------------
  it('4. Detects realistic GitLab token in a test file when no fixture markers exist', () => {
    const realisticGitLabToken = ['glpat-', 'X8q1mP9zL4vR2tW7yK5s'].join('');
    const line = `const deployToken = "${realisticGitLabToken}";`;
    const matches = evaluateLineRules(line, 1, testFilePath);

    expect(matches.length).toBe(1);
    expect(matches[0]?.rule.id).toBe('SEC-GL-001');
    expect(matches[0]?.rule.severity).toBe('CRITICAL');

    const fixtureCheck = isSyntheticTestFixture({
      rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-GL-001')!,
      rawCandidate: realisticGitLabToken,
      lineContent: line,
      lineNumber: 1,
      columnNumber: 21,
      filePath: testFilePath
    });
    expect(fixtureCheck.isSynthetic).toBe(false);
  });

  // --------------------------------------------------------------------------
  // Requirement 4b: Realistic GitHub token in a test file is still detected
  // --------------------------------------------------------------------------
  it('4b. Detects realistic GitHub token in a test file when no fixture markers exist', () => {
    const realisticGitHubToken = ['ghp_', 'X8q1mP9zL4vR2tW7yK5sJ0hN3bV6cM1aQ4eZ'].join('');
    const line = `const gitHubApiKey = "${realisticGitHubToken}";`;
    const matches = evaluateLineRules(line, 1, testFilePath);

    expect(matches.length).toBe(1);
    expect(matches[0]?.rule.id).toBe('SEC-GH-001');
    expect(matches[0]?.rule.severity).toBe('CRITICAL');

    const fixtureCheck = isSyntheticTestFixture({
      rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-GH-001')!,
      rawCandidate: realisticGitHubToken,
      lineContent: line,
      lineNumber: 1,
      columnNumber: 23,
      filePath: testFilePath
    });
    expect(fixtureCheck.isSynthetic).toBe(false);
  });

  // --------------------------------------------------------------------------
  // Requirement 4c: Realistic Database credential in a test file is still detected
  // --------------------------------------------------------------------------
  it('4c. Detects realistic Database connection URI in a test file when no fixture markers exist', () => {
    const password = ['xK9!mP2$qL8', '*vR1!'].join('');
    const dbUri = `postgres://appuser:${password}@db.internal.company.com:5432/production`;
    const line = `const dbUrl = "${dbUri}";`;
    const matches = evaluateLineRules(line, 1, testFilePath);

    expect(matches.length).toBe(1);
    expect(matches[0]?.rule.id).toBe('SEC-DB-001');
    expect(matches[0]?.rule.severity).toBe('CRITICAL');

    const fixtureCheck = isSyntheticTestFixture({
      rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-DB-001')!,
      rawCandidate: password,
      lineContent: line,
      lineNumber: 1,
      columnNumber: 26,
      filePath: testFilePath
    });
    expect(fixtureCheck.isSynthetic).toBe(false);
  });

  // --------------------------------------------------------------------------
  // Requirement 5: Isolated PEM header text does NOT trigger a finding
  // --------------------------------------------------------------------------
  it('5. Does not trigger a finding for isolated PEM headers in assertions, comments, or isolated constants', () => {
    const header = '-----BEGIN RSA PRIVATE KEY-----';

    // 5a. Inside test assertion
    const assertionLine = `expect(redacted).toContain('${header}');`;
    expect(
      isIsolatedPemHeader({
        rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-PK-001')!,
        rawCandidate: header,
        lineContent: assertionLine,
        lineNumber: 10,
        columnNumber: 28,
        filePath: 'tests/scanners/secret/masking.test.ts'
      })
    ).toBe(true);

    // 5b. Inside comment line
    const commentLine = `// Note: PEM headers look like ${header}`;
    expect(
      isIsolatedPemHeader({
        rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-PK-001')!,
        rawCandidate: header,
        lineContent: commentLine,
        lineNumber: 15,
        columnNumber: 32,
        filePath: 'src/scanners/secret/rules.ts'
      })
    ).toBe(true);

    // 5c. Closed single-line string literal assignment
    const closedConstLine = `const pemHeader = '${header}';`;
    expect(
      isIsolatedPemHeader({
        rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-PK-001')!,
        rawCandidate: header,
        lineContent: closedConstLine,
        lineNumber: 20,
        columnNumber: 19,
        filePath: 'tests/auth.test.ts'
      })
    ).toBe(true);

    // 5d. Header with zero payload lines (EOF follows)
    const fileLines = [closedConstLine];
    expect(
      isIsolatedPemHeader({
        rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-PK-001')!,
        rawCandidate: header,
        lineContent: closedConstLine,
        lineNumber: 1,
        columnNumber: 19,
        filePath: 'src/config.ts',
        allLines: fileLines
      })
    ).toBe(true);
  });

  // --------------------------------------------------------------------------
  // Requirement 6: Complete private-key block IS detected
  // --------------------------------------------------------------------------
  it('6. Detects complete private-key block with BEGIN, base64 payload lines, and END marker', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-pk-test-'));
    try {
      const keyFile = path.join(tempDir, 'id_rsa');
      const completeKeyContent = [
        '# Valid private key block',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y9VwN62N14739174981729837128937198273891729387129873918',
        'anotherRealLookingBase64PayloadLineInsideTheCompleteKeyBlock7364826194726==',
        '-----END RSA PRIVATE KEY-----',
        '# End of key'
      ].join('\n');

      fs.writeFileSync(keyFile, completeKeyContent, 'utf-8');

      const result = await scanFileForSecrets(keyFile, tempDir);
      expect(result.findings.length).toBe(1);
      expect(result.findings[0]?.vulnerabilityId).toBe('SEC-PK-001');
      expect(result.findings[0]?.severity).toBe('CRITICAL');
      expect(result.findings[0]?.installedVersion).toBe('L2:C1');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // Requirement 7: Incomplete private-key block IS detected
  // --------------------------------------------------------------------------
  it('7. Detects incomplete private-key block (BEGIN marker with base64 payload to EOF)', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-inc-pk-'));
    try {
      const incompleteFile = path.join(tempDir, 'truncated.pem');
      const incompleteContent = [
        '# Truncated or incomplete private key',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y9VwN62N14739174981729837128937198273891729387129873918',
        'anotherRealLookingBase64PayloadLineInsideTheIncompleteKeyBlock827361846=='
      ].join('\n');

      fs.writeFileSync(incompleteFile, incompleteContent, 'utf-8');

      const result = await scanFileForSecrets(incompleteFile, tempDir);
      expect(result.findings.length).toBe(1);
      expect(result.findings[0]?.vulnerabilityId).toBe('SEC-PK-001');
      expect(result.findings[0]?.severity).toBe('CRITICAL');
      expect(result.findings[0]?.installedVersion).toBe('L2:C1');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // Requirement 8: Private-key body content NEVER appears in finding evidence or output
  // --------------------------------------------------------------------------
  it('8. Ensures private-key payload body never leaks into finding evidence or serialized JSON', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-leak-test-'));
    try {
      const secretFile = path.join(tempDir, 'sensitive.key');
      const sensitivePayload = 'TOP_SECRET_PRIVATE_KEY_BODY_DO_NOT_EXPOSE_7777777777777777777==';
      const keyContent = [
        '-----BEGIN EC PRIVATE KEY-----',
        sensitivePayload,
        '-----END EC PRIVATE KEY-----'
      ].join('\n');

      fs.writeFileSync(secretFile, keyContent, 'utf-8');

      const result = await scanFileForSecrets(secretFile, tempDir);
      expect(result.findings.length).toBe(1);

      const finding = result.findings[0]!;
      expect(finding.evidence.includes(sensitivePayload)).toBe(false);
      expect(finding.evidence).toContain('...[REDACTED]...');

      // Check full JSON serialization
      const jsonOutput = JSON.stringify(result);
      expect(jsonOutput.includes(sensitivePayload)).toBe(false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // --------------------------------------------------------------------------
  // Requirement 9: Existing masking and line-number behavior remains exact and intact
  // --------------------------------------------------------------------------
  it('9. Preserves exact line numbers for findings following multiline PEM blocks', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-lineno-test-'));
    try {
      const mixedFile = path.join(tempDir, 'app.ts');
      const realisticKey = ['AKIA', 'X5T8B4Q1M9K2L3R6'].join('');
      const mixedContent = [
        '// Line 1: Header comment',
        '-----BEGIN RSA PRIVATE KEY-----', // Line 2
        'MIIEowIBAAKCAQEA0Y9VwN62N14739174981729837128937198273891729387129873918', // Line 3
        'anotherRealLookingBase64PayloadLineInsideTheKeyBlock736482619472618938217==', // Line 4
        '-----END RSA PRIVATE KEY-----', // Line 5
        '// Line 6: Intermediate text',
        `const awsKey = "${realisticKey}";`, // Line 7: Realistic AWS key
        '// Line 8: Footer'
      ].join('\n');

      fs.writeFileSync(mixedFile, mixedContent, 'utf-8');

      const result = await scanFileForSecrets(mixedFile, tempDir);
      expect(result.findings.length).toBe(2);

      const pkFinding = result.findings.find((f) => f.vulnerabilityId === 'SEC-PK-001')!;
      const awsFinding = result.findings.find((f) => f.vulnerabilityId === 'SEC-AWS-001')!;

      expect(pkFinding).toBeDefined();
      expect(pkFinding.installedVersion).toBe('L2:C1');

      // Line number for finding after PEM block MUST remain exact (Line 7)
      expect(awsFinding).toBeDefined();
      expect(awsFinding.installedVersion).toBe('L7:C17');
      expect(awsFinding.evidence.includes(realisticKey)).toBe(false);
      expect(awsFinding.evidence).toContain('AKI...[REDACTED]...3R6');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

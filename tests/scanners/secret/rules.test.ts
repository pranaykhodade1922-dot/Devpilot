import { describe, it, expect } from 'vitest';
import {
  BUILT_IN_RULES,
  isPlaceholderOrDummy,
  isTestFilePath,
  evaluateLineRules,
  deduplicateRuleMatches
} from '../../../src/scanners/secret/rules.js';
import { redactSecretFromLine, maskSecret } from '../../../src/scanners/secret/masking.js';

describe('Secret Detection Rules (rules.ts)', () => {
  describe('Placeholder and Dummy Filtering', () => {
    it('detects common placeholder strings', () => {
      expect(isPlaceholderOrDummy('your_api_key_here')).toBe(true);
      expect(isPlaceholderOrDummy('YOUR_SECRET_HERE')).toBe(true);
      expect(isPlaceholderOrDummy('example_token')).toBe(true);
      expect(isPlaceholderOrDummy('changeme')).toBe(true);
      expect(isPlaceholderOrDummy('insert_here')).toBe(true);
      expect(isPlaceholderOrDummy('dummy_key')).toBe(true);
      expect(isPlaceholderOrDummy('sample_key')).toBe(true);
      expect(isPlaceholderOrDummy('')).toBe(true);
      expect(isPlaceholderOrDummy('   ')).toBe(true);
    });

    it('detects template and environment variables', () => {
      expect(isPlaceholderOrDummy('${AWS_SECRET_KEY}')).toBe(true);
      expect(isPlaceholderOrDummy('{{API_TOKEN}}')).toBe(true);
      expect(isPlaceholderOrDummy('$DATABASE_PASSWORD')).toBe(true);
      expect(isPlaceholderOrDummy('<YOUR_API_KEY>')).toBe(true);
      expect(isPlaceholderOrDummy('process.env.SECRET_KEY')).toBe(true);
    });

    it('detects repetitive characters', () => {
      expect(isPlaceholderOrDummy('000000000000')).toBe(true);
      expect(isPlaceholderOrDummy('XXXXXXXXXXXX')).toBe(true);
      expect(isPlaceholderOrDummy('aaaaaaaaaaaa')).toBe(true);
    });

    it('does not filter genuine synthetic secret strings', () => {
      expect(isPlaceholderOrDummy('AKIAIOSFODNN7EXAMPLE')).toBe(false);
      expect(isPlaceholderOrDummy('ghp_0123456789abcdefghijklmnopqrstuv')).toBe(false);
      expect(isPlaceholderOrDummy('AIzaSyD-739485739281749583726154839')).toBe(false);
      expect(isPlaceholderOrDummy('glpat-0123456789abcdefghij')).toBe(false);
    });
  });

  describe('Test File Context Filtering', () => {
    it('identifies test files correctly', () => {
      expect(isTestFilePath('src/app.test.ts')).toBe(true);
      expect(isTestFilePath('tests/unit/auth.spec.js')).toBe(true);
      expect(isTestFilePath('__tests__/login.js')).toBe(true);
      expect(isTestFilePath('fixtures/mock-keys.json')).toBe(true);
      expect(isTestFilePath('src/services/auth.ts')).toBe(false);
      expect(isTestFilePath('config/production.env')).toBe(false);
    });
  });

  describe('Rule Category Detections', () => {
    const dummyPath = 'src/config.ts';

    it('detects Private Key Headers (complete and incomplete blocks)', () => {
      const line1 = '-----BEGIN RSA PRIVATE KEY-----';
      const line2 = '-----BEGIN OPENSSH PRIVATE KEY-----';
      const line3 = '-----BEGIN EC PRIVATE KEY-----';
      const lineIncomplete = '-----BEGIN PRIVATE KEY-----';

      const matches1 = evaluateLineRules(line1, 1, dummyPath);
      const matches2 = evaluateLineRules(line2, 2, dummyPath);
      const matches3 = evaluateLineRules(line3, 3, dummyPath);
      const matchesInc = evaluateLineRules(lineIncomplete, 4, dummyPath);

      expect(matches1.length).toBe(1);
      expect(matches1[0]?.rule.id).toBe('SEC-PK-001');
      expect(matches2[0]?.rule.id).toBe('SEC-PK-001');
      expect(matches3[0]?.rule.id).toBe('SEC-PK-001');
      expect(matchesInc[0]?.rule.id).toBe('SEC-PK-001');

      // Verify evidence redaction works on line
      const rawSecret = line1.slice(matches1[0]?.startOffset, matches1[0]?.endOffset);
      const redacted = redactSecretFromLine(line1, rawSecret);
      expect(redacted).toContain('...[REDACTED]...');
    });

    it('detects AWS Access Key ID (AKIA / ASIA)', () => {
      // Synthetic AWS Access Keys
      const lineAKIA = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";';
      const lineASIA = 'export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7EXAMPLE"';

      const matches1 = evaluateLineRules(lineAKIA, 1, dummyPath);
      const matches2 = evaluateLineRules(lineASIA, 2, dummyPath);

      expect(matches1.length).toBe(1);
      expect(matches1[0]?.rule.id).toBe('SEC-AWS-001');
      expect(matches1[0]?.rule.severity).toBe('CRITICAL');

      expect(matches2.length).toBe(1);
      expect(matches2[0]?.rule.id).toBe('SEC-AWS-001');

      // Verify zero leak in evidence
      const rawSecret = lineAKIA.slice(matches1[0]?.startOffset, matches1[0]?.endOffset);
      expect(rawSecret).toBe('AKIAIOSFODNN7EXAMPLE');
      const redacted = redactSecretFromLine(lineAKIA, rawSecret);
      expect(redacted.includes('IOSFODNN7')).toBe(false);
      expect(redacted).toBe('const awsKey = "AKI...[REDACTED]...PLE";');
    });

    it('detects AWS Secret Access Key assignment with entropy requirement', () => {
      // High-entropy 40-char synthetic secret key
      const line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"';
      const matches = evaluateLineRules(line, 1, dummyPath);

      expect(matches.length).toBe(1);
      expect(matches[0]?.rule.id).toBe('SEC-AWS-002');
      expect(matches[0]?.rule.severity).toBe('CRITICAL');

      // Low-entropy dummy value must be rejected
      const dummyLine = 'aws_secret_access_key = "0000000000000000000000000000000000000000"';
      const dummyMatches = evaluateLineRules(dummyLine, 2, dummyPath);
      expect(dummyMatches.length).toBe(0);
    });

    it('detects Google API / Firebase Keys', () => {
      // Synthetic 39-character AIza key (4 chars prefix 'AIza' + 35 chars = 39 total)
      const line = 'google_key = "AIzaSyD9876543210abcdefghijklmnopqrs123"';
      const matches = evaluateLineRules(line, 1, dummyPath);

      expect(matches.length).toBe(1);
      expect(matches[0]?.rule.id).toBe('SEC-GCP-001');
      expect(matches[0]?.rule.severity).toBe('HIGH');
    });

    it('detects GitHub Personal Access Tokens (classic and fine-grained)', () => {
      // Synthetic 40-char classic token
      const lineGhp = 'const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";';
      // Synthetic fine-grained pat (82 chars of base62 + prefix)
      const linePat =
        'GITHUB_TOKEN="github_pat_11AAAAAAA_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv"';

      const matchesGhp = evaluateLineRules(lineGhp, 1, dummyPath);
      const matchesPat = evaluateLineRules(linePat, 2, dummyPath);

      expect(matchesGhp.length).toBe(1);
      expect(matchesGhp[0]?.rule.id).toBe('SEC-GH-001');

      expect(matchesPat.length).toBe(1);
      expect(matchesPat[0]?.rule.id).toBe('SEC-GH-001');
    });

    it('detects GitLab Personal Access Tokens', () => {
      const line = 'GITLAB_TOKEN="glpat-0123456789abcdefghij"';
      const matches = evaluateLineRules(line, 1, dummyPath);

      expect(matches.length).toBe(1);
      expect(matches[0]?.rule.id).toBe('SEC-GL-001');
    });

    it('detects Slack Tokens (bot and user)', () => {
      const line = 'const slackBot = "xoxb-123456789012-1234567890123-fakeSlackToken99";';
      const matches = evaluateLineRules(line, 1, dummyPath);

      expect(matches.length).toBe(1);
      expect(matches[0]?.rule.id).toBe('SEC-SLACK-001');
    });

    it('detects Database Connection Strings with Credentials', () => {
      const linePostgres =
        'DATABASE_URL="postgres://dbuser:sUp3rS3cr3tP@ss!@db.production.local:5432/main"';
      const lineMongo =
        'mongodb://admin:m0ng0S3cr3tT0k3n@cluster0.mongodb.net/app?retryWrites=true';

      const matches1 = evaluateLineRules(linePostgres, 1, dummyPath);
      const matches2 = evaluateLineRules(lineMongo, 2, dummyPath);

      expect(matches1.length).toBe(1);
      expect(matches1[0]?.rule.id).toBe('SEC-DB-001');

      expect(matches2.length).toBe(1);
      expect(matches2[0]?.rule.id).toBe('SEC-DB-001');

      // Database without password should not match
      const lineNoPass = 'postgres://user@localhost:5432/mydb';
      expect(evaluateLineRules(lineNoPass, 3, dummyPath).length).toBe(0);

      // Database with placeholder password should be filtered
      const linePlaceholder = 'postgres://user:your_password_here@localhost:5432/mydb';
      expect(evaluateLineRules(linePlaceholder, 4, dummyPath).length).toBe(0);
    });

    it('detects Hardcoded Secret & Password Assignments with entropy checks', () => {
      // High-entropy random password
      const line = 'const dbPassword = "xK9#mQ2$vL8*yP1!";';
      const matches = evaluateLineRules(line, 1, dummyPath);

      expect(matches.length).toBe(1);
      expect(matches[0]?.rule.id).toBe('SEC-GEN-001');

      // Trivial or placeholder password must be filtered
      const lineTrivial = 'password = "password123"';
      expect(evaluateLineRules(lineTrivial, 2, dummyPath).length).toBe(0);
    });

    it('detects Generic API Key Assignments', () => {
      // Synthetic 24-character random API key
      const line = 'api_key: "k9ZmP2vL8xQ1wN4bT7yR3uJ6"';
      const matches = evaluateLineRules(line, 1, dummyPath);

      expect(matches.length).toBe(1);
      expect(matches[0]?.rule.id).toBe('SEC-GEN-002');
    });
  });

  describe('Multiple and Overlapping Matches on One Line', () => {
    it('detects multiple distinct secrets on the same line', () => {
      const line =
        'const key = "AKIAIOSFODNN7EXAMPLE"; const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";';

      const matches = evaluateLineRules(line, 1, 'src/config.ts');

      expect(matches.length).toBe(2);
      expect(matches[0]?.rule.id).toBe('SEC-AWS-001');
      expect(matches[1]?.rule.id).toBe('SEC-GH-001');

      // Redaction check: ensure both are redacted
      let redactedLine = line;
      for (const m of matches) {
        const secret = line.slice(m.startOffset, m.endOffset);
        redactedLine = redactSecretFromLine(redactedLine, secret, m.startOffset, m.endOffset);
      }
      expect(redactedLine.includes('AKIAIOSFODNN7EXAMPLE')).toBe(false);
      expect(redactedLine.includes('ghp_0123456789abcdef')).toBe(false);
      expect(redactedLine).toContain('AKI...[REDACTED]...PLE');
      expect(redactedLine).toContain('ghp...[REDACTED]...xyz');
    });

    it('deduplicates overlapping rule matches in favor of higher severity', () => {
      // Simulate two overlapping matches on the same token
      const mockMatches = [
        {
          rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-GEN-002')!, // MODERATE
          startOffset: 10,
          endOffset: 30,
          entropy: 4.5
        },
        {
          rule: BUILT_IN_RULES.find((r) => r.id === 'SEC-AWS-001')!, // CRITICAL
          startOffset: 10,
          endOffset: 30,
          entropy: 4.5
        }
      ];

      const deduped = deduplicateRuleMatches(mockMatches);
      expect(deduped.length).toBe(1);
      expect(deduped[0]?.rule.id).toBe('SEC-AWS-001');
      expect(deduped[0]?.rule.severity).toBe('CRITICAL');
    });
  });

  describe('Test File Nuance & Non-Suppression of Concrete Credentials', () => {
    it('does not suppress concrete credential formats (e.g. AWS or GitHub) in test files', () => {
      const testFilePath = 'tests/auth.test.ts';
      const lineAWS = ['const testKey = "', 'AKIA', 'X5T8B4Q1M9K2L3R6";'].join('');
      const lineGH = ['const token = "', 'ghp_', 'X8q1mP9zL4vR2tW7yK5sJ0hN3bV6cM1aQ4eZ";'].join('');

      const matchesAWS = evaluateLineRules(lineAWS, 1, testFilePath);
      const matchesGH = evaluateLineRules(lineGH, 2, testFilePath);

      // Concrete token formats must still be detected in test files
      expect(matchesAWS.length).toBe(1);
      expect(matchesAWS[0]?.rule.id).toBe('SEC-AWS-001');

      expect(matchesGH.length).toBe(1);
      expect(matchesGH[0]?.rule.id).toBe('SEC-GH-001');
    });

    it('suppresses low-entropy generic test passwords in test files', () => {
      const testFilePath = 'tests/unit/login.test.ts';
      // Low-medium entropy mock password common in unit test assertions
      const line = 'const password = "my_mock_password";';

      const matches = evaluateLineRules(line, 1, testFilePath);
      expect(matches.length).toBe(0);
    });
  });
});

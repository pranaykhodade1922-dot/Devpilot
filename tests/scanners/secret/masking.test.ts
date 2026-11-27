import { describe, it, expect } from 'vitest';
import {
  maskSecret,
  redactPrivateKeyBlocks,
  redactLineSpans,
  redactSecretFromLine
} from '../../../src/scanners/secret/masking.js';

describe('Zero-Leak Secret Masking', () => {
  describe('maskSecret()', () => {
    it('returns 8 asterisks for empty or falsy inputs', () => {
      expect(maskSecret('')).toBe('********');
      // @ts-expect-error test undefined input
      expect(maskSecret(undefined)).toBe('********');
    });

    it('fully redacts short secrets (<= 8 characters) to 8 asterisks', () => {
      // Synthetic test credentials
      const shortPin = '1234';
      const shortPass = 'secret88';

      const maskedPin = maskSecret(shortPin);
      const maskedPass = maskSecret(shortPass);

      expect(maskedPin).toBe('********');
      expect(maskedPass).toBe('********');

      // Invariant: raw characters must never appear
      expect(maskedPin.includes(shortPin)).toBe(false);
      expect(maskedPass.includes(shortPass)).toBe(false);
    });

    it('partially masks medium secrets (9 to 16 chars) preserving only 2-char prefix/suffix', () => {
      const mediumKey = 'fake_key_12345'; // 14 chars
      const masked = maskSecret(mediumKey);

      expect(masked.startsWith('fa')).toBe(true);
      expect(masked.endsWith('45')).toBe(true);
      expect(masked).toBe('fa****45');

      // The sensitive middle must not appear
      expect(masked.includes('_key_123')).toBe(false);
    });

    it('safely masks long secrets (> 16 chars) with [REDACTED] indicator', () => {
      const longKey = 'AKIAIOSFODNN7EXAMPLEKEY'; // 23 chars
      const masked = maskSecret(longKey);

      expect(masked.startsWith('AKI')).toBe(true);
      expect(masked.endsWith('KEY')).toBe(true);
      expect(masked).toBe('AKI...[REDACTED]...KEY');

      // The sensitive middle must not appear
      expect(masked.includes('IOSFODNN7EXAMPLE')).toBe(false);
    });
  });

  describe('redactPrivateKeyBlocks()', () => {
    it('completely redacts multiline private key bodies while preserving exact line count', () => {
      const lines = [
        '# Header comment',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y9V...fake_base64_payload...1234567890abcdef==',
        'MIIBogIBAAKCAQEAzFakeMiddlePayloadRowTwo==',
        '-----END RSA PRIVATE KEY-----',
        '# Footer comment'
      ];
      const syntheticKey = lines.join('\n');

      const redacted = redactPrivateKeyBlocks(syntheticKey);
      const redactedLines = redacted.split('\n');

      expect(redactedLines.length).toBe(lines.length);
      expect(redacted).toContain('-----BEGIN RSA PRIVATE KEY-----');
      expect(redacted).toContain('[REDACTED PRIVATE KEY LINE]');
      expect(redacted).toContain('-----END RSA PRIVATE KEY-----');

      // The actual key body payload must not appear anywhere in output
      expect(redacted.includes('fake_base64_payload')).toBe(false);
      expect(redacted.includes('FakeMiddlePayloadRowTwo')).toBe(false);
    });

    it('redacts OPENSSH and EC private keys correctly', () => {
      const sshKey = [
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn',
        '-----END OPENSSH PRIVATE KEY-----'
      ].join('\n');

      const redacted = redactPrivateKeyBlocks(sshKey);
      expect(redacted).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');
      expect(redacted).toContain('[REDACTED PRIVATE KEY LINE]');
      expect(redacted).toContain('-----END OPENSSH PRIVATE KEY-----');
      expect(redacted.includes('b3BlbnNzaC')).toBe(false);
    });

    it('handles incomplete or unclosed PEM blocks by redacting all payload lines to EOF', () => {
      const incompleteKey = [
        '# Start',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y9V...fake_payload_without_end_marker',
        'another_sensitive_base64_line=='
      ].join('\n');

      const redacted = redactPrivateKeyBlocks(incompleteKey);
      const redactedLines = redacted.split('\n');

      expect(redactedLines.length).toBe(4);
      expect(redactedLines[0]).toBe('# Start');
      expect(redactedLines[1]).toBe('-----BEGIN RSA PRIVATE KEY-----');
      expect(redactedLines[2]).toBe('[REDACTED PRIVATE KEY LINE]');
      expect(redactedLines[3]).toBe('[REDACTED PRIVATE KEY LINE]');

      expect(redacted.includes('fake_payload_without_end_marker')).toBe(false);
      expect(redacted.includes('another_sensitive_base64_line')).toBe(false);
    });

    it('redacts multiple distinct private key blocks in a single input file', () => {
      const multiKey = [
        '# Key 1',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y9V...first_payload',
        '-----END RSA PRIVATE KEY-----',
        '# Key 2',
        '-----BEGIN EC PRIVATE KEY-----',
        'MIIBogIBAAKCAQEAzFake...second_payload',
        '-----END EC PRIVATE KEY-----',
        '# Done'
      ].join('\n');

      const redacted = redactPrivateKeyBlocks(multiKey);
      const redactedLines = redacted.split('\n');

      expect(redactedLines.length).toBe(9);
      expect(redactedLines[1]).toBe('-----BEGIN RSA PRIVATE KEY-----');
      expect(redactedLines[2]).toBe('[REDACTED PRIVATE KEY LINE]');
      expect(redactedLines[3]).toBe('-----END RSA PRIVATE KEY-----');

      expect(redactedLines[5]).toBe('-----BEGIN EC PRIVATE KEY-----');
      expect(redactedLines[6]).toBe('[REDACTED PRIVATE KEY LINE]');
      expect(redactedLines[7]).toBe('-----END EC PRIVATE KEY-----');

      expect(redacted.includes('first_payload')).toBe(false);
      expect(redacted.includes('second_payload')).toBe(false);
    });

    it('safely handles mismatched BEGIN and END key markers', () => {
      const mismatched = [
        '# Mismatched Key',
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y9V...fake_payload_row_one',
        '-----END EC PRIVATE KEY-----', // Mismatched key type
        'MIIEowIBAAKCAQEA0Y9V...fake_payload_row_two',
        '-----END RSA PRIVATE KEY-----'
      ].join('\n');

      const redacted = redactPrivateKeyBlocks(mismatched);

      // Intermediate lines and mismatched footer cannot expose raw payload
      expect(redacted.includes('fake_payload_row_one')).toBe(false);
      expect(redacted.includes('fake_payload_row_two')).toBe(false);
    });
  });

  describe('redactLineSpans() & Overlapping Spans', () => {
    it('redacts multiple non-overlapping secrets on a single line', () => {
      // line: 'user=admin&token=abcdefghijklmnopq&pw=12345678'
      const line = 'user=admin&token=abcdefghijklmnopq&pw=12345678';
      const tokenSpan = { start: 17, end: 34 }; // 'abcdefghijklmnopq' (17 chars)
      const pwSpan = { start: 38, end: 46 }; // '12345678' (8 chars)

      const redacted = redactLineSpans(line, [tokenSpan, pwSpan]);

      expect(redacted.includes('abcdefghijklmnopq')).toBe(false);
      expect(redacted.includes('12345678')).toBe(false);
      expect(redacted).toContain('user=admin&token=abc...[REDACTED]...opq&pw=********');
    });

    it('correctly merges and redacts overlapping spans without leakage', () => {
      const line = 'api_secret_key="my_super_secret_token_123"';
      // span 1: 'my_super_secret' (index 16..31)
      // span 2: 'secret_token_123' (index 25..41)
      const span1 = { start: 16, end: 31 };
      const span2 = { start: 25, end: 41 };

      const redacted = redactLineSpans(line, [span1, span2]);

      // Entire overlapping combined range (16..41) is masked
      expect(redacted.includes('my_super_secret')).toBe(false);
      expect(redacted.includes('secret_token_123')).toBe(false);
      expect(redacted.startsWith('api_secret_key="')).toBe(true);
      expect(redacted.endsWith('"')).toBe(true);
    });

    it('handles out-of-order and boundary spans gracefully', () => {
      const line = 'FOO=BAR';
      const span = { start: 4, end: 7 }; // 'BAR'
      const redacted = redactLineSpans(line, [span]);
      expect(redacted).toBe('FOO=********');
    });
  });

  describe('redactSecretFromLine()', () => {
    it('redacts exact occurrences of a secret from a source code line', () => {
      const rawSecret = 'fake_secret_token_9999';
      const line = `const apiKey = "${rawSecret}";`;

      const redacted = redactSecretFromLine(line, rawSecret);

      expect(redacted.includes(rawSecret)).toBe(false);
      expect(redacted).toBe('const apiKey = "fak...[REDACTED]...999";');
    });

    it('redacts using specific offsets when provided', () => {
      const rawSecret = 'fake_secret_token_9999';
      const line = `const apiKey = "${rawSecret}";`;
      const start = line.indexOf(rawSecret);
      const end = start + rawSecret.length;

      const redacted = redactSecretFromLine(line, rawSecret, start, end);

      expect(redacted.includes(rawSecret)).toBe(false);
      expect(redacted).toContain('fak...[REDACTED]...999');
    });
  });
});

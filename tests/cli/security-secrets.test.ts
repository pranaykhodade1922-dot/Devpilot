import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createProgram } from '../../src/cli/index.js';
import {
  runSecuritySecrets,
  runSecurityDeps,
  CLI_EXIT_CODES
} from '../../src/cli/commands/security.js';

describe('CLI Integration: devpilot security secrets', () => {
  let tempDir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let originalExitCode: number | undefined;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-cli-test-'));
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    originalExitCode = process.exitCode;
    process.exitCode = 0;
  });

  afterEach(() => {
    logSpy.mockRestore();
    process.exitCode = originalExitCode;
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  describe('Commander Registration', () => {
    it('registers the "security secrets" command with options and arguments', () => {
      const program = createProgram();
      const securityCmd = program.commands.find((cmd) => cmd.name() === 'security');
      expect(securityCmd).toBeDefined();

      const secretsCmd = securityCmd?.commands.find((cmd) => cmd.name() === 'secrets');
      expect(secretsCmd).toBeDefined();
      expect(secretsCmd?.description()).toContain('Scan project files for hardcoded secrets');

      // Check for [path] argument
      const pathArg = secretsCmd?.registeredArguments.find((arg) => arg.name() === 'path');
      expect(pathArg).toBeDefined();
      expect(pathArg?.required).toBe(false);

      // Check for --json option
      const jsonOpt = secretsCmd?.options.find((opt) => opt.long === '--json');
      expect(jsonOpt).toBeDefined();
    });

    it('preserves existing "security deps" command registration', () => {
      const program = createProgram();
      const securityCmd = program.commands.find((cmd) => cmd.name() === 'security');
      const depsCmd = securityCmd?.commands.find((cmd) => cmd.name() === 'deps');
      expect(depsCmd).toBeDefined();
      expect(depsCmd?.description()).toContain('Scan project dependencies');
    });
  });

  describe('Command Execution & Exit Codes', () => {
    it('returns Exit Code 0 (CLEAN) on a project with no secrets', async () => {
      fs.writeFileSync(path.join(tempDir, 'main.ts'), 'export const title = "Clean Project";\n');

      const result = await runSecuritySecrets(tempDir);

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.findingsCount).toBe(0);
      expect(process.exitCode).toBe(CLI_EXIT_CODES.CLEAN);
      expect(process.exitCode).toBe(0);

      const logs = logSpy.mock.calls.map((call) => call.join(' ')).join('\n');
      expect(logs).toContain('No Secrets Detected (Exit Code 0)');
      expect(logs).toContain('DevPilot Security — Secret Scanner');
    });

    it('returns Exit Code 1 (VULNERABLE) on a project with detected secrets and redacts raw secrets in output', async () => {
      // Fake test credential matching AWS access key pattern
      const fakeAwsKey = 'AKIAIOSFODNN7EXAMPLE';
      fs.writeFileSync(
        path.join(tempDir, 'credentials.env'),
        `AWS_ACCESS_KEY_ID="${fakeAwsKey}"\n`
      );

      const result = await runSecuritySecrets(tempDir);

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.summary.findingsCount).toBeGreaterThanOrEqual(1);
      expect(process.exitCode).toBe(CLI_EXIT_CODES.VULNERABLE);
      expect(process.exitCode).toBe(1);

      const logs = logSpy.mock.calls.map((call) => call.join(' ')).join('\n');
      expect(logs).toContain('Total Findings:');
      expect(logs).toContain('SEC-AWS-001');

      // CRITICAL: Raw secret must NOT be leaked to console output
      expect(logs).not.toContain(fakeAwsKey);
      // Masked secret representation must appear instead
      expect(logs).toContain('AKI...[REDACTED]...PLE');
    });

    it('returns Exit Code 2 (FAILED) when scanning a non-existent path', async () => {
      const nonExistentPath = path.join(tempDir, 'does-not-exist-dir');

      const result = await runSecuritySecrets(nonExistentPath);

      expect(result.summary.scanStatus).toBe('FAILED');
      expect(process.exitCode).toBe(CLI_EXIT_CODES.FAILED);
      expect(process.exitCode).toBe(2);

      const logs = logSpy.mock.calls.map((call) => call.join(' ')).join('\n');
      expect(logs).toContain('Scan Failed (Exit Code 2)');
    });

    it('returns Exit Code 3 (PARTIAL) when files exceed max size or cannot be read', async () => {
      // Create a file > 2MB (default maxFileSize) to trigger errorSkipped / TOO_LARGE
      const largeFilePath = path.join(tempDir, 'large-data.txt');
      const largeContent = 'A'.repeat(2 * 1024 * 1024 + 1024); // 2MB + 1KB
      fs.writeFileSync(largeFilePath, largeContent);

      const result = await runSecuritySecrets(tempDir);

      expect(result.summary.scanStatus).toBe('PARTIAL');
      expect(result.summary.errorSkippedCount).toBeGreaterThanOrEqual(1);
      expect(process.exitCode).toBe(CLI_EXIT_CODES.PARTIAL);
      expect(process.exitCode).toBe(3);

      const logs = logSpy.mock.calls.map((call) => call.join(' ')).join('\n');
      expect(logs).toContain('Scan Partially Completed (Exit Code 3)');
    });

    it('outputs valid JSON without ANSI codes when --json is passed', async () => {
      const fakeGoogleKey = 'AIzaSy' + 'A'.repeat(33);
      fs.writeFileSync(
        path.join(tempDir, 'config.ts'),
        `const apiKey = "${fakeGoogleKey}";\n`
      );

      const result = await runSecuritySecrets(tempDir, { json: true });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(process.exitCode).toBe(CLI_EXIT_CODES.VULNERABLE);

      expect(logSpy).toHaveBeenCalledTimes(1);
      const jsonOutput = logSpy.mock.calls[0][0];

      // Parse JSON to verify correctness
      const parsed = JSON.parse(jsonOutput);
      expect(parsed).toHaveProperty('summary');
      expect(parsed).toHaveProperty('findings');
      expect(parsed.summary.findingsCount).toBe(1);
      expect(parsed.findings[0].vulnerabilityId).toBe('SEC-GCP-001');

      // CRITICAL: Ensure raw secret is NOT present in parsed JSON or raw output
      expect(jsonOutput).not.toContain(fakeGoogleKey);
      expect(parsed.findings[0].evidence).toContain('[REDACTED]');
    });

    it('defaults to current working directory when targetPath is omitted', async () => {
      // Running against devpilot's own working directory
      // (The devpilot repo itself has no unmasked real secrets in tracked source)
      const result = await runSecuritySecrets(undefined);

      expect(result).toBeDefined();
      expect(result.summary.totalFilesScanned).toBeGreaterThan(0);
      expect(result.summary.scanStatus).toBeDefined();
    });
  });

  describe('Non-regression of dependency scanner', () => {
    it('runs runSecurityDeps with fatal exit code on empty directory lacking lockfile', async () => {
      const result = await runSecurityDeps(tempDir);
      expect(result.summary.scanStatus).toBe('FAILED');
      expect(process.exitCode).toBe(CLI_EXIT_CODES.FAILED);
      expect(process.exitCode).toBe(2);
    });
  });
});

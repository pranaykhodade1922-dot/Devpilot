import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createProgram } from '../../src/cli/index.js';
import {
  runScan,
  determineUnifiedExitCode
} from '../../src/cli/commands/scan.js';
import {
  runSecurityDeps,
  runSecuritySecrets,
  CLI_EXIT_CODES
} from '../../src/cli/commands/security.js';
import { runDoctor } from '../../src/cli/commands/doctor.js';

describe('CLI Integration: devpilot scan (Unified Security Scanner)', () => {
  let tempDir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let originalExitCode: number | undefined;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-unified-test-'));
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
      // Ignore cleanup error on windows
    }
  });

  describe('Commander Registration & Help Discovery', () => {
    it('registers the "scan [path]" command with --json option', () => {
      const program = createProgram();
      const scanCmd = program.commands.find((cmd) => cmd.name() === 'scan');
      expect(scanCmd).toBeDefined();
      expect(scanCmd?.description()).toContain('Run unified security scan');

      const pathArg = scanCmd?.registeredArguments.find((arg) => arg.name() === 'path');
      expect(pathArg).toBeDefined();
      expect(pathArg?.required).toBe(false);

      const jsonOpt = scanCmd?.options.find((opt) => opt.long === '--json');
      expect(jsonOpt).toBeDefined();
    });

    it('formats structured help output for devpilot --help', () => {
      const program = createProgram();
      const help = program.helpInformation();

      // Check organized sections
      expect(help).toContain('MAIN COMMANDS');
      expect(help).toContain('scan [path]');
      expect(help).toContain('SECURITY COMMANDS');
      expect(help).toContain('security deps [path]');
      expect(help).toContain('security secrets [path]');
      expect(help).toContain('UTILITY COMMANDS');
      expect(help).toContain('doctor');
      expect(help).toContain('help [command]');

      // Check required examples
      expect(help).toContain('EXAMPLES');
      expect(help).toContain('$ devpilot scan');
      expect(help).toContain('$ devpilot scan ./my-project');
      expect(help).toContain('$ devpilot security deps');
      expect(help).toContain('$ devpilot security secrets --json');
      expect(help).toContain('$ devpilot doctor');
    });

    it('formats detailed help output for devpilot scan --help', () => {
      const program = createProgram();
      const scanCmd = program.commands.find((cmd) => cmd.name() === 'scan');
      expect(scanCmd).toBeDefined();

      const help = scanCmd?.helpInformation();
      expect(help).toContain('--json');
      expect(help).toContain('Examples:');
      expect(help).toContain('$ devpilot scan');
      expect(help).toContain('$ devpilot scan ./my-project');
      expect(help).toContain('$ devpilot scan --json');
    });
  });

  describe('Exit Code Aggregation Rules', () => {
    it('returns CLEAN (0) when all scanners complete with 0 findings', () => {
      const result = determineUnifiedExitCode('COMPLETED', 'COMPLETED', 0);
      expect(result.scanStatus).toBe('CLEAN');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.CLEAN);
      expect(result.exitCode).toBe(0);
    });

    it('returns CLEAN (0) when dependency scan is skipped and secret scan completes with 0 findings', () => {
      const result = determineUnifiedExitCode('SKIPPED', 'COMPLETED', 0);
      expect(result.scanStatus).toBe('CLEAN');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.CLEAN);
      expect(result.exitCode).toBe(0);
    });

    it('returns VULNERABLE (1) when scanners complete and findings are detected', () => {
      const result = determineUnifiedExitCode('COMPLETED', 'COMPLETED', 3);
      expect(result.scanStatus).toBe('VULNERABLE');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.VULNERABLE);
      expect(result.exitCode).toBe(1);
    });

    it('returns FAILED (2) if dependency scanner fails', () => {
      const result = determineUnifiedExitCode('FAILED', 'COMPLETED', 0);
      expect(result.scanStatus).toBe('FAILED');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.FAILED);
      expect(result.exitCode).toBe(2);
    });

    it('returns FAILED (2) if secret scanner fails', () => {
      const result = determineUnifiedExitCode('COMPLETED', 'FAILED', 0);
      expect(result.scanStatus).toBe('FAILED');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.FAILED);
      expect(result.exitCode).toBe(2);
    });

    it('returns FAILED (2) even if findings exist (fatal failure is never hidden)', () => {
      const result = determineUnifiedExitCode('FAILED', 'COMPLETED', 5);
      expect(result.scanStatus).toBe('FAILED');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.FAILED);
      expect(result.exitCode).toBe(2);
    });

    it('returns PARTIAL (3) if any scanner reports partial results', () => {
      const result = determineUnifiedExitCode('COMPLETED', 'PARTIAL', 0);
      expect(result.scanStatus).toBe('PARTIAL');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.PARTIAL);
      expect(result.exitCode).toBe(3);
    });

    it('returns FAILED (2) over PARTIAL (3) if one scanner fails and another is partial', () => {
      const result = determineUnifiedExitCode('FAILED', 'PARTIAL', 2);
      expect(result.scanStatus).toBe('FAILED');
      expect(result.exitCode).toBe(CLI_EXIT_CODES.FAILED);
      expect(result.exitCode).toBe(2);
    });

    it('handles 4-parameter call including SAST status: FAILED (2) and PARTIAL (3)', () => {
      const failedSast = determineUnifiedExitCode('COMPLETED', 'COMPLETED', 'FAILED', 0);
      expect(failedSast.scanStatus).toBe('FAILED');
      expect(failedSast.exitCode).toBe(CLI_EXIT_CODES.FAILED);

      const partialSast = determineUnifiedExitCode('COMPLETED', 'COMPLETED', 'PARTIAL', 0);
      expect(partialSast.scanStatus).toBe('PARTIAL');
      expect(partialSast.exitCode).toBe(CLI_EXIT_CODES.PARTIAL);

      const vulnSast = determineUnifiedExitCode('COMPLETED', 'COMPLETED', 'COMPLETED', 2);
      expect(vulnSast.scanStatus).toBe('VULNERABLE');
      expect(vulnSast.exitCode).toBe(CLI_EXIT_CODES.VULNERABLE);
    });
  });

  describe('Unified Command Execution & Reporting', () => {
    it('executes a clean scan on a project with valid lockfile and clean files (Exit 0)', async () => {
      // Setup clean npm project
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'clean-app', version: '1.0.0' }, null, 2)
      );
      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify({ name: 'clean-app', lockfileVersion: 3, packages: {} }, null, 2)
      );
      fs.writeFileSync(path.join(tempDir, 'index.ts'), 'export const hello = "world";\n');

      const result = await runScan(tempDir);

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.totalFindings).toBe(0);
      expect(result.summary.scanners.dependency.status).toBe('COMPLETED');
      expect(result.summary.scanners.secret.status).toBe('COMPLETED');
      expect(result.summary.scanners.sast.status).toBe('COMPLETED');
      expect(process.exitCode).toBe(0);

      const logs = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logs).toContain('DevPilot Security Report');
      expect(logs).toContain('Project:');
      expect(logs).toContain('Dependency Scanner: Completed');
      expect(logs).toContain('Secret Scanner:     Completed');
      expect(logs).toContain('SAST Scanner:       Completed');
      expect(logs).toContain('No Security Findings Detected (Exit Code 0)');
    });

    it('detects SAST vulnerabilities and coordinates report with SAST badge (Exit 1)', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'sast-vuln-app', version: '1.0.0' }, null, 2)
      );
      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify({ name: 'sast-vuln-app', lockfileVersion: 3, packages: {} }, null, 2)
      );
      fs.writeFileSync(
        path.join(tempDir, 'query.ts'),
        `
        import { Client } from 'pg';
        const client = new Client();
        export function getUser(userId: string) {
          return client.query('SELECT * FROM users WHERE id = ' + userId);
        }
        `
      );

      const result = await runScan(tempDir);

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.summary.scanners.sast.findingsCount).toBeGreaterThanOrEqual(1);
      expect(result.summary.totalFindings).toBeGreaterThanOrEqual(1);
      expect(process.exitCode).toBe(1);

      const logs = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logs).toContain('SAST Scanner:       Completed');
      expect(logs).toContain('SEC-SAST-SQL-INJECTION');
      expect(logs).toContain('SAST');
    });

    it('skips dependency scan when no package.json exists but completes secret scan (Exit 0)', async () => {
      fs.writeFileSync(path.join(tempDir, 'script.py'), 'print("Hello from Python")\n');

      const result = await runScan(tempDir);

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.scanners.dependency.status).toBe('SKIPPED');
      expect(result.summary.scanners.secret.status).toBe('COMPLETED');
      expect(process.exitCode).toBe(0);

      const logs = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logs).toContain('Dependency Scanner: Skipped');
      expect(logs).toContain('Secret Scanner:     Completed');
    });

    it('detects secrets, reports findings, and redacts raw secrets in output (Exit 1)', async () => {
      const fakeApiKey = 'AKIAIOSFODNN7EXAMPLE';
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'vuln-app', version: '1.0.0' }, null, 2)
      );
      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify({ name: 'vuln-app', lockfileVersion: 3, packages: {} }, null, 2)
      );
      fs.writeFileSync(
        path.join(tempDir, 'keys.env'),
        `AWS_ACCESS_KEY_ID="${fakeApiKey}"\n`
      );

      const result = await runScan(tempDir);

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.summary.totalFindings).toBeGreaterThanOrEqual(1);
      expect(result.summary.severityCounts.CRITICAL).toBeGreaterThanOrEqual(1);
      expect(process.exitCode).toBe(1);

      const logs = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logs).toContain('Total findings:');
      expect(logs).toContain('SEC-AWS-001');

      // CRITICAL: Raw secret must NOT be in stdout
      expect(logs).not.toContain(fakeApiKey);
      expect(logs).toContain('AKI...[REDACTED]...PLE');
    });

    it('returns Exit 2 (FAILED) when package.json exists but lockfile is missing', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'missing-lockfile-app', version: '1.0.0' }, null, 2)
      );
      fs.writeFileSync(path.join(tempDir, 'index.ts'), 'console.log("no lockfile");\n');

      const result = await runScan(tempDir);

      expect(result.summary.scanStatus).toBe('FAILED');
      expect(result.summary.scanners.dependency.status).toBe('FAILED');
      expect(process.exitCode).toBe(2);

      const logs = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logs).toContain('Scan Failed (Exit Code 2)');
      expect(logs).toContain('Dependency Scanner:');
    });

    it('retains findings from successful Secret and SAST scanners even when Dependency scanner fails', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'failing-dep-app', version: '1.0.0' }, null, 2)
      );
      // Missing lockfile causes Dependency Scanner to fail
      fs.writeFileSync(
        path.join(tempDir, 'index.ts'),
        `
        import { Client } from 'pg';
        const client = new Client();
        client.query('SELECT * FROM users WHERE id = ' + userId);
        `
      );

      const result = await runScan(tempDir);

      expect(result.summary.scanStatus).toBe('FAILED');
      expect(result.summary.scanners.dependency.status).toBe('FAILED');
      expect(result.summary.scanners.sast.status).toBe('COMPLETED');
      // SAST finding must NOT be discarded
      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      expect(result.summary.totalFindings).toBeGreaterThanOrEqual(1);
      expect(process.exitCode).toBe(2);
    });

    it('returns Exit 3 (PARTIAL) when eligible files exceed size limit or cannot be read', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'partial-app', version: '1.0.0' }, null, 2)
      );
      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify({ name: 'partial-app', lockfileVersion: 3, packages: {} }, null, 2)
      );
      // Large file > 2MB
      const hugeFile = path.join(tempDir, 'big.txt');
      fs.writeFileSync(hugeFile, 'B'.repeat(2 * 1024 * 1024 + 512));

      const result = await runScan(tempDir);

      expect(result.summary.scanStatus).toBe('PARTIAL');
      expect(result.summary.scanners.secret.status).toBe('PARTIAL');
      expect(process.exitCode).toBe(3);

      const logs = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logs).toContain('Scan Partially Completed (Exit Code 3)');
    });

    it('outputs machine-readable JSON without ANSI styling when --json is provided', async () => {
      const fakeToken = 'ghp_' + 'B'.repeat(36);
      fs.writeFileSync(
        path.join(tempDir, 'config.ts'),
        `const githubToken = "${fakeToken}";\n`
      );

      const result = await runScan(tempDir, { json: true });

      expect(result).toBeDefined();
      expect(logSpy).toHaveBeenCalledTimes(1);

      const jsonStr = logSpy.mock.calls[0][0];
      const parsed = JSON.parse(jsonStr);

      expect(parsed).toHaveProperty('summary');
      expect(parsed).toHaveProperty('findings');
      expect(parsed.summary.scanners.dependency).toBeDefined();
      expect(parsed.summary.scanners.secret).toBeDefined();
      expect(parsed.findings.length).toBeGreaterThanOrEqual(1);

      // Raw secret must not appear in JSON
      expect(jsonStr).not.toContain(fakeToken);
      expect(parsed.findings[0].evidence).toContain('[REDACTED]');
    });

    it('defaults to current working directory when path is omitted', async () => {
      const result = await runScan();
      expect(result).toBeDefined();
      expect(result.summary.projectRoot).toBe(process.cwd());
    });
  });

  describe('Non-regression of individual commands', () => {
    it('runs devpilot security deps independently', async () => {
      const result = await runSecurityDeps(tempDir);
      expect(result).toBeDefined();
      expect(result.summary.scanStatus).toBeDefined();
    });

    it('runs devpilot security secrets independently', async () => {
      const result = await runSecuritySecrets(tempDir);
      expect(result).toBeDefined();
      expect(result.summary.scanStatus).toBeDefined();
    });

    it('runs devpilot doctor without errors', () => {
      expect(() => runDoctor()).not.toThrow();
    });
  });
});

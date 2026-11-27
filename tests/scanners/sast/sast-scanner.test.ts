import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { scanSast, computeSastScanStatus } from '../../../src/scanners/sast/sast-scanner.js';
import { determineSastExitCode } from '../../../src/cli/commands/security.js';

describe('SAST Scanner Integration (sast-scanner.ts)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sast-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows
    }
  });

  it('scans a project directory and accurately reports vulnerable findings with exact locations', async () => {
    const srcDir = path.join(tempDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    // 1. Vulnerable file with eval and exec
    const file1 = path.join(srcDir, 'runner.ts');
    fs.writeFileSync(
      file1,
      [
        "import { exec } from 'child_process';",
        'export function runUserTask(task: string) {',
        '  eval(task);', // Line 3
        '  exec(`sh ${task}`);', // Line 4
        '}'
      ].join('\n'),
      'utf-8'
    );

    // 2. Safe file
    const file2 = path.join(srcDir, 'safe.ts');
    fs.writeFileSync(
      file2,
      [
        "import { execFile } from 'child_process';",
        'export function safeRun() {',
        "  execFile('git', ['status']);",
        '}'
      ].join('\n'),
      'utf-8'
    );

    const result = await scanSast({ cwd: tempDir });

    expect(result.summary.totalFilesScanned).toBe(2);
    expect(result.summary.findingsCount).toBe(2);
    expect(result.summary.scanStatus).toBe('VULNERABLE');
    expect(determineSastExitCode(result.summary)).toBe(1);

    const evalFinding = result.findings.find((f) => f.ruleId === 'SEC-SAST-EVAL');
    expect(evalFinding).toBeDefined();
    expect(evalFinding?.severity).toBe('CRITICAL');
    expect(evalFinding?.location?.filePath).toBe('src/runner.ts');
    expect(evalFinding?.location?.line).toBe(3);

    const execFinding = result.findings.find((f) => f.ruleId === 'SEC-SAST-COMMAND-INJECTION');
    expect(execFinding).toBeDefined();
    expect(execFinding?.severity).toBe('CRITICAL');
    expect(execFinding?.location?.line).toBe(4);
  });

  it('masks secret values if they happen to appear in SAST snippet evidence', async () => {
    const srcDir = path.join(tempDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    const keyPart = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
    const file = path.join(srcDir, 'leaky.ts');
    fs.writeFileSync(
      file,
      [
        "import { exec } from 'child_process';",
        `const awsKey = "${keyPart}";`,
        'eval(awsKey);'
      ].join('\n'),
      'utf-8'
    );

    const result = await scanSast({ cwd: tempDir });
    expect(result.findings.length).toBe(1);

    const finding = result.findings[0]!;
    // Raw secret key MUST be redacted from evidence
    expect(finding.evidence.includes('IOSFODNN7')).toBe(false);
  });

  it('marks scan as PARTIAL when files contain recoverable syntax errors (never falsely CLEAN)', async () => {
    const srcDir = path.join(tempDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    // File with syntax error
    const brokenFile = path.join(srcDir, 'broken.ts');
    fs.writeFileSync(
      brokenFile,
      'function broken( { const x = 1;', // missing closing paren
      'utf-8'
    );

    const result = await scanSast({ cwd: tempDir });
    expect(result.summary.hasSyntaxErrors).toBe(true);
    // Crucial: status must be PARTIAL (Exit code 3), never CLEAN
    expect(result.summary.scanStatus).toBe('PARTIAL');
    expect(determineSastExitCode(result.summary)).toBe(3);

    const errorSkipped = result.summary.skippedFiles.find((s) => s.reason === 'PARTIAL_ANALYSIS');
    expect(errorSkipped).toBeDefined();
    expect(errorSkipped?.filePath).toBe('src/broken.ts');
  });

  it('returns CLEAN with Exit Code 0 when all scanned files are safe and free of syntax errors', async () => {
    const srcDir = path.join(tempDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    const safeFile = path.join(srcDir, 'pure.ts');
    fs.writeFileSync(
      safeFile,
      [
        'export function add(a: number, b: number): number {',
        '  return a + b;',
        '}'
      ].join('\n'),
      'utf-8'
    );

    const result = await scanSast({ cwd: tempDir });
    expect(result.summary.findingsCount).toBe(0);
    expect(result.summary.scanStatus).toBe('CLEAN');
    expect(determineSastExitCode(result.summary)).toBe(0);
  });

  it('computes scan status transitions deterministically', () => {
    expect(computeSastScanStatus(0, false, 0)).toBe('CLEAN');
    expect(computeSastScanStatus(2, false, 0)).toBe('VULNERABLE');
    expect(computeSastScanStatus(2, true, 0)).toBe('VULNERABLE'); // Findings take priority over partial
    expect(computeSastScanStatus(0, true, 0)).toBe('PARTIAL'); // Syntax errors without findings -> PARTIAL
    expect(computeSastScanStatus(0, false, 1)).toBe('PARTIAL'); // Unreadable files -> PARTIAL
  });
});

import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../../src/scanners/sast/parser.js';
import { analyzeSourceFile } from '../../../../src/scanners/sast/analyzer.js';
import { RULE_SEC_SAST_COMMAND_INJECTION } from '../../../../src/scanners/sast/rules/exec.js';

describe('SAST Rule: SEC-SAST-COMMAND-INJECTION', () => {
  it('detects dynamic child_process.exec() with template literal as CRITICAL / MEDIUM confidence', () => {
    const code = `
      import { exec } from 'child_process';
      function pingHost(host: string) {
        exec(\`ping -c 1 \${host}\`);
      }
    `;
    const { sourceFile } = parseSourceCode('src/network.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/network.ts',
      relPath: 'src/network.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_COMMAND_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('SEC-SAST-COMMAND-INJECTION');
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[0]?.confidence).toBe('MEDIUM');
    expect(findings[0]?.location?.line).toBe(4);
    expect(findings[0]?.evidence).toContain('exec(`ping -c 1 ${host}`)');
  });

  it('detects renamed import and string concatenation with execSync', () => {
    const code = `
      import { execSync as runShell } from 'node:child_process';
      function buildProject(branch: string) {
        runShell('git checkout ' + branch);
      }
    `;
    const { sourceFile } = parseSourceCode('src/build.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/build.ts',
      relPath: 'src/build.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_COMMAND_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('CRITICAL');
  });

  it('detects namespace imports (import * as cp from child_process)', () => {
    const code = `
      import * as cp from 'child_process';
      function run(task: string) {
        cp.exec(task);
      }
    `;
    const { sourceFile } = parseSourceCode('src/runner.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/runner.ts',
      relPath: 'src/runner.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_COMMAND_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('CRITICAL');
  });

  it('detects CommonJS require destructuring and namespace declarations', () => {
    const code = `
      const { exec } = require('child_process');
      const cp = require('node:child_process');
      exec(commandA);
      cp.execSync(commandB);
    `;
    const { sourceFile } = parseSourceCode('src/legacy.js', code);
    const findings = analyzeSourceFile({
      filePath: 'src/legacy.js',
      relPath: 'src/legacy.js',
      sourceFile,
      rules: [RULE_SEC_SAST_COMMAND_INJECTION]
    });

    expect(findings.length).toBe(2);
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[1]?.severity).toBe('CRITICAL');
  });

  it('reports static compile-time command with LOW severity', () => {
    const code = `
      import { exec } from 'child_process';
      exec('git status');
    `;
    const { sourceFile } = parseSourceCode('src/git.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/git.ts',
      relPath: 'src/git.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_COMMAND_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('LOW');
    expect(findings[0]?.confidence).toBe('HIGH');
  });

  it('does NOT flag safe execFile or unrelated RegExp.prototype.exec methods', () => {
    const code = `
      import { execFile } from 'child_process';
      execFile('git', ['status']); // Safe API

      const pattern = /hello/g;
      pattern.exec('hello world'); // RegExp method, not child_process
    `;
    const { sourceFile } = parseSourceCode('src/safe.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/safe.ts',
      relPath: 'src/safe.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_COMMAND_INJECTION]
    });

    expect(findings.length).toBe(0);
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ProgressCoordinator } from '../../src/cli/ui/progress-coordinator.js';
import { TerminalPresenter, formatCounts } from '../../src/cli/ui/progress.js';
import { runScan } from '../../src/cli/commands/scan.js';
import { runSecurityDeps, runSecuritySecrets, runSecuritySast } from '../../src/cli/commands/security.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Milestone 2.3 Phase 3 — Progress Coordinator & Presenter', () => {
  describe('TerminalPresenter and formatCounts', () => {
    it('formats completed and total counts without inventing percentages', () => {
      expect(formatCounts(5, 10)).toBe('5/10');
      expect(formatCounts(0, 5)).toBe('0/5');
      expect(formatCounts(42)).toBe('42');
      expect(formatCounts(42, undefined)).toBe('42');
      expect(formatCounts(undefined, 10)).toBe('');
    });

    it('writes non-interactive lines when animation is disabled', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const presenter = new TerminalPresenter({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1' }
      });

      presenter.updateLine('First progress update');
      // Duplicate should be suppressed in non-interactive
      presenter.updateLine('First progress update');
      presenter.updateLine('Second progress update');
      presenter.logPermanent('Completed task');

      expect(output).toContain('First progress update\n');
      expect(output).toContain('Second progress update\n');
      expect(output).toContain('Completed task\n');
      expect(output.split('First progress update').length - 1).toBe(1);
    });
  });

  describe('ProgressCoordinator Event Dispatching', () => {
    it('receives dependency, secret, and SAST events and tracks counts accurately', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1', NO_COLOR: '1' }
      });

      // 1. Dependency event
      coordinator.onDependencyProgress({
        stage: 'querying',
        status: 'progress',
        completed: 2,
        total: 4,
        message: 'Querying OSV batches'
      });

      // 2. Secret event
      coordinator.onSecretProgress({
        stage: 'scanning',
        status: 'progress',
        completed: 15,
        total: 30,
        message: 'Scanning files'
      });

      // 3. SAST event
      coordinator.onSastProgress({
        stage: 'analyzing',
        status: 'progress',
        completed: 7,
        total: 10,
        message: 'Analyzing source ASTs'
      });

      expect(output).toContain('Dependency Scanner: Querying OSV batches (2/4)');
      expect(output).toContain('Secret Scanner: Scanning files (15/30)');
      expect(output).toContain('SAST Scanner: Analyzing source ASTs (7/10)');
    });

    it('renders clean completed terminal status when scan has zero findings', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1', NO_COLOR: '1' }
      });

      coordinator.onDependencyProgress({
        stage: 'completed',
        status: 'completed',
        outcome: 'clean',
        metadata: { findingsCount: 0 }
      });

      expect(output).toContain('Dependency Scanner [CLEAN] — 0 issues detected');
    });

    it('renders vulnerable status when scan has findings', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1', NO_COLOR: '1' }
      });

      coordinator.onSecretProgress({
        stage: 'completed',
        status: 'completed',
        outcome: 'vulnerable',
        metadata: { findingsCount: 3 }
      });

      expect(output).toContain('Secret Scanner [VULNERABLE] — 3 issue(s) found');
    });

    it('renders partial coverage without clean status when partial with zero findings', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1', NO_COLOR: '1' }
      });

      coordinator.onSastProgress({
        stage: 'completed',
        status: 'partial',
        // outcome omitted for partial with zero findings
        metadata: { findingsCount: 0 }
      });

      expect(output).toContain('SAST Scanner [PARTIAL] — Incomplete coverage; cannot establish clean result');
      expect(output).not.toContain('[CLEAN]');
    });

    it('renders partial coverage with vulnerable note when partial with findings', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1', NO_COLOR: '1' }
      });

      coordinator.onSastProgress({
        stage: 'completed',
        status: 'partial',
        outcome: 'vulnerable',
        metadata: { findingsCount: 2 }
      });

      expect(output).toContain('SAST Scanner [PARTIAL COVERAGE (VULNERABLE)] — 2 issue(s) detected; incomplete coverage');
    });

    it('renders failed status with error message', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1', NO_COLOR: '1' }
      });

      coordinator.onDependencyProgress({
        stage: 'completed',
        status: 'failed',
        message: 'Lockfile could not be found'
      });

      expect(output).toContain('Dependency Scanner [FAILED] — Lockfile could not be found');
    });

    it('renders skipped scanners cleanly', () => {
      let output = '';
      const mockStream = {
        write: vi.fn().mockImplementation((chunk: string) => {
          output += chunk;
          return true;
        }),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        env: { NO_ANIMATION: '1', NO_COLOR: '1' }
      });

      coordinator.markSkipped('dependency', 'No package.json detected in project');

      expect(output).toContain('Dependency Scanner (Skipped: No package.json detected in project)');
    });

    it('silences all output completely when silent option is enabled for JSON mode', () => {
      const mockStream = {
        write: vi.fn(),
        isTTY: false
      };

      const coordinator = new ProgressCoordinator({
        stream: mockStream as any,
        silent: true
      });

      coordinator.start();
      coordinator.onDependencyProgress({
        stage: 'querying',
        status: 'progress',
        completed: 1,
        total: 10
      });
      coordinator.onSecretProgress({
        stage: 'completed',
        status: 'completed',
        outcome: 'clean'
      });
      coordinator.markSkipped('sast', 'Skipped');
      coordinator.stop();

      expect(mockStream.write).not.toHaveBeenCalled();
    });

    it('swallows exceptions inside event handling without crashing', () => {
      const badStream = {
        get isTTY() {
          throw new Error('Terminal pipe broken');
        },
        write: () => {
          throw new Error('Write error');
        }
      };

      const coordinator = new ProgressCoordinator({
        stream: badStream as any
      });

      expect(() => {
        coordinator.onDependencyProgress({
          stage: 'querying',
          status: 'progress'
        });
      }).not.toThrow();
    });
  });

  describe('CLI Command Execution & JSON Compliance', () => {
    let tempDir: string;

    beforeEach(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-cli-test-'));
      // Create minimal clean package.json & lockfile
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({ name: 'test-proj', version: '1.0.0' }, null, 2)
      );
      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(
          {
            name: 'test-proj',
            version: '1.0.0',
            lockfileVersion: 3,
            packages: { '': { name: 'test-proj' } }
          },
          null,
          2
        )
      );
      // Clean source file
      fs.writeFileSync(path.join(tempDir, 'index.ts'), 'export const cleanValue = 10;\n');
    });

    afterEach(() => {
      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('devpilot scan --json outputs purely valid JSON without banners or progress text', async () => {
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      try {
        const result = await runScan(tempDir, { json: true });
        expect(result).toBeDefined();

        // Exactly one call to console.log containing JSON
        expect(consoleLogSpy).toHaveBeenCalledTimes(1);
        const output = consoleLogSpy.mock.calls[0]![0];

        // Must parse as valid JSON
        const parsed = JSON.parse(output);
        expect(parsed.summary).toBeDefined();
        expect(parsed.findings).toEqual([]);
        expect(parsed.summary.scanStatus).toBe('CLEAN');

        // Verify no ANSI or decoration strings
        expect(output).not.toContain('DevPilot Security');
        expect(output).not.toContain('─');
      } finally {
        consoleLogSpy.mockRestore();
      }
    });

    it('devpilot security deps --json outputs purely valid JSON', async () => {
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      try {
        const result = await runSecurityDeps(tempDir, { json: true });
        expect(result).toBeDefined();

        expect(consoleLogSpy).toHaveBeenCalledTimes(1);
        const output = consoleLogSpy.mock.calls[0]![0];
        const parsed = JSON.parse(output);
        expect(parsed.summary).toBeDefined();
        expect(parsed.findings).toEqual([]);
      } finally {
        consoleLogSpy.mockRestore();
      }
    });

    it('devpilot security secrets --json outputs purely valid JSON', async () => {
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      try {
        const result = await runSecuritySecrets(tempDir, { json: true });
        expect(result).toBeDefined();

        expect(consoleLogSpy).toHaveBeenCalledTimes(1);
        const output = consoleLogSpy.mock.calls[0]![0];
        const parsed = JSON.parse(output);
        expect(parsed.summary).toBeDefined();
        expect(parsed.findings).toEqual([]);
      } finally {
        consoleLogSpy.mockRestore();
      }
    });

    it('devpilot security sast --json outputs purely valid JSON', async () => {
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      try {
        const result = await runSecuritySast(tempDir, { json: true });
        expect(result).toBeDefined();

        expect(consoleLogSpy).toHaveBeenCalledTimes(1);
        const output = consoleLogSpy.mock.calls[0]![0];
        const parsed = JSON.parse(output);
        expect(parsed.summary).toBeDefined();
        expect(parsed.findings).toEqual([]);
      } finally {
        consoleLogSpy.mockRestore();
      }
    });

    it('unified scan displays banner and progress in non-JSON mode', async () => {
      const logs: string[] = [];
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation((...args) => {
        logs.push(args.join(' '));
      });

      try {
        const result = await runScan(tempDir, { json: false });
        expect(result.summary.scanStatus).toBe('CLEAN');

        const joined = logs.join('\n');
        expect(joined).toContain('DevPilot Security');
        expect(joined).toContain('Project:');
        expect(joined).toContain('Scan Duration:');
      } finally {
        consoleLogSpy.mockRestore();
      }
    });
  });
});

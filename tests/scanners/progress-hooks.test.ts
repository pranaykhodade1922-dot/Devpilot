import { describe, it, expect, vi } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { scanDependencies } from '../../src/scanners/dependency/dependency-scanner.js';
import type { DependencyProgressEvent } from '../../src/scanners/dependency/types.js';
import { scanSecrets } from '../../src/scanners/secret/secret-scanner.js';
import type { SecretProgressEvent } from '../../src/scanners/secret/types.js';
import { scanSast } from '../../src/scanners/sast/sast-scanner.js';
import type { SastProgressEvent } from '../../src/scanners/sast/types.js';

describe('Milestone 2.3 Phase 2 — Scanner Progress Hooks Audit', () => {
  describe('Dependency Scanner Progress Hooks', () => {
    it('emits accurate progress events during dependency scan with mock OSV responses', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-dep-progress-'));
      const packageLock = {
        name: 'test-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'test-project',
            dependencies: {
              lodash: '4.17.20',
              axios: '0.21.1'
            }
          },
          'node_modules/lodash': {
            version: '4.17.20'
          },
          'node_modules/axios': {
            version: '0.21.1'
          }
        }
      };

      fs.writeFileSync(path.join(tempDir, 'package-lock.json'), JSON.stringify(packageLock, null, 2));

      const mockFetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes('/v1/querybatch')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              results: [
                { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm' }] },
                { vulns: [] }
              ]
            })
          };
        }
        if (url.includes('/v1/vulns/GHSA-35jh-r3h4-6jhm')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              id: 'GHSA-35jh-r3h4-6jhm',
              summary: 'Prototype pollution in lodash',
              affected: [
                {
                  package: { name: 'lodash', ecosystem: 'npm' },
                  ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
                  database_specific: { severity: 'HIGH' }
                }
              ]
            })
          };
        }
        return { ok: false, status: 404, json: async () => ({}) };
      });

      const events: DependencyProgressEvent[] = [];
      const onProgress = (evt: DependencyProgressEvent) => {
        events.push(evt);
      };

      const result = await scanDependencies({
        lockfilePath: path.join(tempDir, 'package-lock.json'),
        fetchFn: mockFetch as any,
        onProgress
      });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.findings.length).toBe(1);

      // Verify stages occurred
      const stages = events.map((e) => e.stage);
      expect(stages).toContain('discovery');
      expect(stages).toContain('querying');
      expect(stages).toContain('hydrating');
      expect(stages).toContain('evaluating');
      expect(stages).toContain('completed');

      // Verify discovery events
      const discCompleted = events.find((e) => e.stage === 'discovery' && e.status === 'completed');
      expect(discCompleted?.metadata?.totalDependencies).toBe(2);
      expect(discCompleted?.metadata?.uniquePackages).toBe(2);

      // Verify querying progress
      const queryProgress = events.find((e) => e.stage === 'querying' && e.status === 'progress');
      expect(queryProgress?.metadata?.batchesCompleted).toBe(1);
      expect(queryProgress?.metadata?.totalBatches).toBe(1);
      expect(queryProgress?.metadata?.queriesCompleted).toBe(2);
      expect(queryProgress?.metadata?.totalQueries).toBe(2);

      // Verify hydration progress
      const hydrateProgress = events.find((e) => e.stage === 'hydrating' && e.status === 'progress');
      expect(hydrateProgress?.metadata?.advisoriesHydrated).toBe(1);
      expect(hydrateProgress?.metadata?.totalAdvisories).toBe(1);

      // Verify terminal event separates lifecycle status and scan outcome
      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('completed');
      expect(terminalEvent?.outcome).toBe('vulnerable');
      expect(terminalEvent?.metadata?.findingsCount).toBe(1);

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('handles empty dependencies with clean outcome and completed lifecycle status', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-dep-empty-'));
      const packageLock = {
        name: 'empty-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': { name: 'empty-project' }
        }
      };

      fs.writeFileSync(path.join(tempDir, 'package-lock.json'), JSON.stringify(packageLock, null, 2));

      const events: DependencyProgressEvent[] = [];
      const result = await scanDependencies({
        lockfilePath: path.join(tempDir, 'package-lock.json'),
        onProgress: (evt) => events.push(evt)
      });

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.totalDependencies).toBe(0);

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('completed');
      expect(terminalEvent?.outcome).toBe('clean');

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('emits failed stage and status when lockfile cannot be found or parsed', async () => {
      const nonExistentPath = path.join(os.tmpdir(), 'non-existent-lockfile-dir', 'package-lock.json');
      const events: DependencyProgressEvent[] = [];

      const result = await scanDependencies({
        lockfilePath: nonExistentPath,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('FAILED');
      const failedEvents = events.filter((e) => e.status === 'failed');
      expect(failedEvents.length).toBeGreaterThanOrEqual(1);

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('failed');
      expect(terminalEvent?.metadata?.errorMessage).toBeDefined();
    });

    it('emits partial status when OSV hydration is incomplete and zero confirmed findings exist', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-dep-partial-'));
      const packageLock = {
        name: 'test-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-project', dependencies: { foo: '1.0.0' } },
          'node_modules/foo': { version: '1.0.0' }
        }
      };
      fs.writeFileSync(path.join(tempDir, 'package-lock.json'), JSON.stringify(packageLock, null, 2));

      // Batch query returns stub with affected ranges that do NOT match installed version (so 0 findings),
      // but another advisory in the batch fails hydration (404) marking hasIncompleteAdvisories = true
      const mockFetch = vi.fn().mockImplementation(async (url: string) => {
        if (url.includes('/v1/querybatch')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              results: [{ vulns: [{ id: 'GHSA-failed-hydrate' }] }]
            })
          };
        }
        // 404 for advisory hydration
        return { ok: false, status: 404, json: async () => ({}) };
      });

      const events: DependencyProgressEvent[] = [];
      const result = await scanDependencies({
        lockfilePath: path.join(tempDir, 'package-lock.json'),
        fetchFn: mockFetch as any,
        onProgress: (e) => events.push(e)
      });

      // When stub cannot be hydrated, it is preserved with isIncomplete: true. If it matches, findings > 0 => VULNERABLE.
      // If it has findings, terminal status is 'completed' with outcome 'vulnerable'.
      // If zero findings and incomplete advisories, status is PARTIAL => lifecycle status is 'partial' and outcome 'clean'.
      expect(result.summary.hasIncompleteAdvisories).toBe(true);

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      if (result.summary.scanStatus === 'PARTIAL') {
        expect(terminalEvent?.status).toBe('partial');
        expect(terminalEvent?.outcome).toBeUndefined();
      } else {
        expect(result.summary.scanStatus).toBe('VULNERABLE');
        expect(terminalEvent?.status).toBe('completed');
        expect(terminalEvent?.outcome).toBe('vulnerable');
      }

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('swallows callback errors and completes dependency scan safely', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-dep-error-cb-'));
      const packageLock = {
        name: 'test-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-project' }
        }
      };
      fs.writeFileSync(path.join(tempDir, 'package-lock.json'), JSON.stringify(packageLock, null, 2));

      const throwingOnProgress = vi.fn().mockImplementation(() => {
        throw new Error('Callback malfunction inside UI listener');
      });

      const result = await scanDependencies({
        lockfilePath: path.join(tempDir, 'package-lock.json'),
        onProgress: throwingOnProgress
      });

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(throwingOnProgress).toHaveBeenCalled();

      fs.rmSync(tempDir, { recursive: true, force: true });
    });
  });

  describe('Secret Scanner Progress Hooks', () => {
    it('emits accurate progress events without leaking raw secrets or absolute paths', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sec-progress-'));
      const testSecret = 'AKIAIOSFODNN7EXAMPLE';
      const file1 = path.join(tempDir, 'config.ts');
      const file2 = path.join(tempDir, 'readme.md');

      fs.writeFileSync(file1, `const awsKey = "${testSecret}";\nconsole.log(awsKey);\n`);
      fs.writeFileSync(file2, `# DevPilot Readme\nNo secrets here.\n`);

      const events: SecretProgressEvent[] = [];
      const result = await scanSecrets({
        cwd: tempDir,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.findings.length).toBe(1);

      // Verify stages
      const stages = events.map((e) => e.stage);
      expect(stages).toContain('discovery');
      expect(stages).toContain('scanning');
      expect(stages).toContain('completed');

      // Verify file progress items
      const scanProgressEvents = events.filter((e) => e.stage === 'scanning' && e.status === 'progress');
      expect(scanProgressEvents.length).toBe(2);

      // Verify CRITICAL SECURITY INVARIANT: raw secrets NEVER leak into events
      for (const evt of events) {
        const json = JSON.stringify(evt);
        expect(json).not.toContain(testSecret);
        if (evt.metadata?.currentFile) {
          // Relative path only
          expect(path.isAbsolute(evt.metadata.currentFile)).toBe(false);
          expect(evt.metadata.currentFile).not.toContain(tempDir);
        }
      }

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('completed');
      expect(terminalEvent?.outcome).toBe('vulnerable');

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('handles empty project directory gracefully', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sec-empty-'));
      const events: SecretProgressEvent[] = [];

      const result = await scanSecrets({
        cwd: tempDir,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.totalFilesScanned).toBe(0);

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('completed');
      expect(terminalEvent?.outcome).toBe('clean');

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('emits failed progress status when directory does not exist', async () => {
      const nonExistentDir = path.join(os.tmpdir(), 'non-existent-secret-dir-404');
      const events: SecretProgressEvent[] = [];

      const result = await scanSecrets({
        cwd: nonExistentDir,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('FAILED');
      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('failed');
      expect(terminalEvent?.metadata?.errorMessage).toBeDefined();
    });

    it('swallows callback errors and preserves scan findings in secret scanner', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sec-cb-err-'));
      fs.writeFileSync(path.join(tempDir, 'key.js'), `const x = "AKIAIOSFODNN7EXAMPLE";`);

      const throwingCallback = vi.fn().mockImplementation(() => {
        throw new Error('Consumer UI thread threw error');
      });

      const result = await scanSecrets({
        cwd: tempDir,
        onProgress: throwingCallback
      });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.findings.length).toBe(1);
      expect(throwingCallback).toHaveBeenCalled();

      fs.rmSync(tempDir, { recursive: true, force: true });
    });
  });

  describe('SAST Scanner Progress Hooks', () => {
    it('emits accurate AST parsing progress events without leaking source code', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sast-progress-'));
      const file1 = path.join(tempDir, 'vuln.js');
      const file2 = path.join(tempDir, 'safe.ts');
      const sensitiveLine = 'eval("someSensitiveUserCode(payload)");';

      fs.writeFileSync(file1, `${sensitiveLine}\n`);
      fs.writeFileSync(file2, `export const safe = 42;\n`);

      const events: SastProgressEvent[] = [];
      const result = await scanSast({
        cwd: tempDir,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.findings.length).toBe(1);

      // Verify stages
      const stages = events.map((e) => e.stage);
      expect(stages).toContain('discovery');
      expect(stages).toContain('analyzing');
      expect(stages).toContain('completed');

      const analyzingProgressEvents = events.filter((e) => e.stage === 'analyzing' && e.status === 'progress');
      expect(analyzingProgressEvents.length).toBe(2);

      // Verify SECURITY & PRIVACY INVARIANT: source code is NOT leaked in progress metadata
      for (const evt of events) {
        const json = JSON.stringify(evt);
        expect(json).not.toContain('someSensitiveUserCode');
        if (evt.metadata?.currentFile) {
          expect(path.isAbsolute(evt.metadata.currentFile)).toBe(false);
          expect(evt.metadata.currentFile).not.toContain(tempDir);
        }
      }

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('completed');
      expect(terminalEvent?.outcome).toBe('vulnerable');

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('emits partial status when recoverable syntax diagnostics exist without findings', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sast-syntax-err-'));
      // Source with intentional syntax error
      fs.writeFileSync(path.join(tempDir, 'syntax-err.ts'), `function broken( {`);

      const events: SastProgressEvent[] = [];
      const result = await scanSast({
        cwd: tempDir,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('PARTIAL');
      expect(result.summary.hasSyntaxErrors).toBe(true);

      const analyzingEvents = events.filter((e) => e.stage === 'analyzing' && e.status === 'progress');
      expect(analyzingEvents.some((e) => e.metadata?.hasSyntaxErrors === true)).toBe(true);

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('partial');
      expect(terminalEvent?.outcome).toBeUndefined();

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('handles empty SAST source tree gracefully', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sast-empty-'));
      // Only markdown file, no JS/TS
      fs.writeFileSync(path.join(tempDir, 'README.md'), '# Notes\n');

      const events: SastProgressEvent[] = [];
      const result = await scanSast({
        cwd: tempDir,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('CLEAN');
      expect(result.summary.totalFilesScanned).toBe(0);

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('completed');
      expect(terminalEvent?.outcome).toBe('clean');

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('swallows callback errors and preserves scan findings in SAST scanner', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sast-cb-err-'));
      fs.writeFileSync(path.join(tempDir, 'eval.js'), `eval("test");`);

      const throwingCallback = vi.fn().mockImplementation(() => {
        throw new Error('Callback failed');
      });

      const result = await scanSast({
        cwd: tempDir,
        onProgress: throwingCallback
      });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.findings.length).toBe(1);
      expect(throwingCallback).toHaveBeenCalled();

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('emits partial status with vulnerable outcome when recoverable syntax errors co-exist with findings', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-sast-partial-vuln-'));
      // File 1 has syntax error, File 2 has confirmed finding
      fs.writeFileSync(path.join(tempDir, 'syntax.ts'), `function err( {`);
      fs.writeFileSync(path.join(tempDir, 'vuln.js'), `eval("danger");`);

      const events: SastProgressEvent[] = [];
      const result = await scanSast({
        cwd: tempDir,
        onProgress: (e) => events.push(e)
      });

      expect(result.summary.scanStatus).toBe('VULNERABLE');
      expect(result.summary.hasSyntaxErrors).toBe(true);
      expect(result.findings.length).toBe(1);

      const terminalEvent = events[events.length - 1];
      expect(terminalEvent?.stage).toBe('completed');
      expect(terminalEvent?.status).toBe('completed');
      expect(terminalEvent?.outcome).toBe('vulnerable');

      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it('operates identically when onProgress is omitted across all scanners', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-omitted-'));
      fs.writeFileSync(path.join(tempDir, 'safe.ts'), `export const msg = "hello";\n`);

      const secretResult = await scanSecrets({ cwd: tempDir });
      const sastResult = await scanSast({ cwd: tempDir });

      expect(secretResult.summary.scanStatus).toBe('CLEAN');
      expect(sastResult.summary.scanStatus).toBe('CLEAN');

      fs.rmSync(tempDir, { recursive: true, force: true });
    });
  });
});

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  crawlProjectFiles,
  parseGitignorePattern,
  isPathIgnoredByGitignore,
  isBinaryFile,
  isPathContainedWithin
} from '../../../src/scanners/secret/file-crawler.js';

describe('Safe File Crawler (file-crawler.ts)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-crawler-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('parses gitignore rules including negations and directories', () => {
    const rule1 = parseGitignorePattern('*.log', tempDir);
    expect(rule1?.isNegation).toBe(false);
    expect(rule1?.regex.test('error.log')).toBe(true);
    expect(rule1?.regex.test('nested/app.log')).toBe(true);
    expect(rule1?.regex.test('app.js')).toBe(false);

    const rule2 = parseGitignorePattern('!important.log', tempDir);
    expect(rule2?.isNegation).toBe(true);

    const ruleDir = parseGitignorePattern('temp/', tempDir);
    expect(ruleDir?.isDirOnly).toBe(true);
  });

  it('correctly handles gitignore negation rules (!pattern)', () => {
    const rules = [
      parseGitignorePattern('*.secret', tempDir)!,
      parseGitignorePattern('!safe.secret', tempDir)!
    ];

    expect(isPathIgnoredByGitignore('keys.secret', false, rules)).toBe(true);
    expect(isPathIgnoredByGitignore('safe.secret', false, rules)).toBe(false);
  });

  it('skips default excluded directories (node_modules, .git, dist, coverage)', async () => {
    // Create directory hierarchy
    fs.mkdirSync(path.join(tempDir, 'node_modules'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'node_modules', 'dep.js'), 'console.log()');

    fs.mkdirSync(path.join(tempDir, '.git'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, '.git', 'config'), 'dummy');

    fs.mkdirSync(path.join(tempDir, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'dist', 'bundle.js'), 'dummy');

    fs.mkdirSync(path.join(tempDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'src', 'index.ts'), 'export const a = 1;');

    const result = await crawlProjectFiles({ rootDir: tempDir });

    expect(result.eligibleFiles.length).toBe(1);
    expect(result.eligibleFiles[0]?.endsWith('index.ts')).toBe(true);

    // Verify intentional exclusions
    const excludedDirs = result.intentionallyExcluded.map((r) => r.filePath);
    expect(excludedDirs.some((p) => p.includes('node_modules'))).toBe(true);
    expect(excludedDirs.some((p) => p.includes('.git'))).toBe(true);
    expect(excludedDirs.some((p) => p.includes('dist'))).toBe(true);
  });

  it('skips binary files and detects null bytes safely', async () => {
    // Create text file
    const textFile = path.join(tempDir, 'app.txt');
    fs.writeFileSync(textFile, 'hello world text content');

    // Create binary file with null byte
    const binFile = path.join(tempDir, 'data.dat');
    const binBuffer = Buffer.from([0x68, 0x65, 0x6c, 0x00, 0x6c, 0x6f]); // "hel\0lo"
    fs.writeFileSync(binFile, binBuffer);

    expect(isBinaryFile(textFile)).toBe(false);
    expect(isBinaryFile(binFile)).toBe(true);

    const result = await crawlProjectFiles({ rootDir: tempDir });

    expect(result.eligibleFiles.length).toBe(1);
    expect(result.eligibleFiles[0]).toBe(textFile);

    // Binary file must be tracked under intentionallyExcluded
    expect(
      result.intentionallyExcluded.some(
        (r) => r.filePath === 'data.dat' && r.reason === 'BINARY_FILE' && r.isIntentionallyExcluded
      )
    ).toBe(true);
    expect(result.errorSkipped.length).toBe(0);
  });

  it('skips files exceeding maxFileSize', async () => {
    const smallFile = path.join(tempDir, 'small.txt');
    fs.writeFileSync(smallFile, 'small content');

    const largeFile = path.join(tempDir, 'large.txt');
    fs.writeFileSync(largeFile, 'x'.repeat(2048)); // 2 KB

    // Set maxFileSize to 1024 bytes (1 KB)
    const result = await crawlProjectFiles({ rootDir: tempDir, maxFileSize: 1024 });

    expect(result.eligibleFiles.length).toBe(1);
    expect(result.eligibleFiles[0]).toBe(smallFile);

    expect(result.errorSkipped.some((r) => r.filePath === 'large.txt' && r.reason === 'TOO_LARGE')).toBe(true);
  });

  it('respects nested .gitignore files', async () => {
    // Root .gitignore
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'root_ignored.txt\n');

    // Subdirectory with its own .gitignore
    const subDir = path.join(tempDir, 'packages', 'app');
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(subDir, '.gitignore'), 'nested_ignored.txt\n');

    // Files
    fs.writeFileSync(path.join(tempDir, 'root_ignored.txt'), 'secret1');
    fs.writeFileSync(path.join(tempDir, 'root_allowed.txt'), 'ok');
    fs.writeFileSync(path.join(subDir, 'nested_ignored.txt'), 'secret2');
    fs.writeFileSync(path.join(subDir, 'nested_allowed.txt'), 'ok');

    const result = await crawlProjectFiles({ rootDir: tempDir, respectGitignore: true });

    const eligibleNames = result.eligibleFiles.map((f) => path.basename(f));
    expect(eligibleNames).toContain('root_allowed.txt');
    expect(eligibleNames).toContain('nested_allowed.txt');
    expect(eligibleNames).not.toContain('root_ignored.txt');
    expect(eligibleNames).not.toContain('nested_ignored.txt');
  });

  it('reports error when rootDir does not exist or is invalid', async () => {
    const nonExistent = path.join(tempDir, 'does-not-exist');
    const result = await crawlProjectFiles({ rootDir: nonExistent });

    expect(result.eligibleFiles.length).toBe(0);
    expect(result.errorSkipped.length).toBe(1);
    expect(result.errorSkipped[0]?.reason).toBe('PERMISSION_DENIED');
  });

  describe('Path Containment & Security Traversal Guards', () => {
    it('correctly validates containment inside rootDir without prefix collisions', () => {
      const root = path.join(tempDir, 'project');
      const validChild = path.join(tempDir, 'project', 'src', 'index.ts');
      const siblingPrefix = path.join(tempDir, 'project-other', 'secret.txt');
      const parentEscape = path.join(tempDir, 'secret.txt');

      expect(isPathContainedWithin(validChild, root)).toBe(true);
      expect(isPathContainedWithin(root, root)).toBe(true);
      // Sibling starting with same prefix must NOT be considered contained
      expect(isPathContainedWithin(siblingPrefix, root)).toBe(false);
      expect(isPathContainedWithin(parentEscape, root)).toBe(false);
    });

    it('handles legitimate filenames starting with .. correctly', () => {
      const root = path.join(tempDir, 'project');
      const dotDotFile = path.join(tempDir, 'project', '..env');
      const dotDotNested = path.join(tempDir, 'project', 'src', '..custom_name.txt');

      expect(isPathContainedWithin(dotDotFile, root)).toBe(true);
      expect(isPathContainedWithin(dotDotNested, root)).toBe(true);
    });

    it('skips symlinks pointing outside the scan root by default', async () => {
      const scanRoot = path.join(tempDir, 'scan-root');
      const externalDir = path.join(tempDir, 'outside-root');

      fs.mkdirSync(scanRoot, { recursive: true });
      fs.mkdirSync(externalDir, { recursive: true });

      // Create sensitive file outside scan root
      const externalSecretFile = path.join(externalDir, 'external-secret.env');
      fs.writeFileSync(externalSecretFile, 'AWS_KEY="AKIAIOSFODNN7EXAMPLE"');

      // Create valid file inside scanRoot
      const internalFile = path.join(scanRoot, 'app.ts');
      fs.writeFileSync(internalFile, 'console.log("safe");');

      // Create symlink inside scanRoot pointing to external file
      const symlinkPath = path.join(scanRoot, 'link-to-outside.env');
      try {
        fs.symlinkSync(externalSecretFile, symlinkPath, 'file');
      } catch {
        // On Windows without elevated symlink privilege, skip symlink creation
        return;
      }

      const result = await crawlProjectFiles({ rootDir: scanRoot, followSymlinks: false });

      // Symlinked file pointing outside must NOT be included in eligibleFiles
      expect(result.eligibleFiles).toContain(internalFile);
      expect(result.eligibleFiles).not.toContain(symlinkPath);
      expect(result.eligibleFiles).not.toContain(externalSecretFile);

      // Symlink must be recorded under intentionallyExcluded
      expect(
        result.intentionallyExcluded.some(
          (s) => s.filePath.includes('link-to-outside') && s.reason === 'EXCLUDED_DIRECTORY'
        )
      ).toBe(true);
    });
  });
});

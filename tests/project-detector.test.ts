import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { detectProject } from '../src/core/project-detector.js';

describe('Project Detector', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows locks
    }
  });

  it('detects a valid Node.js project with package.json', () => {
    const pkg = {
      name: 'sample-node-app',
      version: '1.0.0',
      dependencies: {
        express: '^4.19.0'
      }
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg, null, 2));
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');

    const result = detectProject({ cwd: tempDir });

    expect(result.projectName).toBe('sample-node-app');
    expect(result.packageJsonExists).toBe(true);
    expect(result.packageManager).toBe('npm');
    expect(result.language).toBe('JavaScript');
    expect(result.framework).toBe('Express');
    expect(result.details.isMalformedPackageJson).toBe(false);
  });

  it('detects a TypeScript project via tsconfig.json and typescript dependency', () => {
    const pkg = {
      name: 'sample-ts-app',
      devDependencies: {
        typescript: '^5.0.0'
      }
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg, null, 2));
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'pnpm-lock.yaml'), '');

    const result = detectProject({ cwd: tempDir });

    expect(result.projectName).toBe('sample-ts-app');
    expect(result.packageJsonExists).toBe(true);
    expect(result.packageManager).toBe('pnpm');
    expect(result.language).toBe('TypeScript');
    expect(result.details.hasTypeScriptConfig).toBe(true);
    expect(result.details.hasTypeScriptDependency).toBe(true);
  });

  it('detects TypeScript from source files (.ts or .tsx) even without explicit config', () => {
    const pkg = {
      name: 'ts-source-app'
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg, null, 2));
    const srcDir = path.join(tempDir, 'src');
    fs.mkdirSync(srcDir);
    fs.writeFileSync(path.join(srcDir, 'index.ts'), 'console.log("hello");');

    const result = detectProject({ cwd: tempDir });

    expect(result.language).toBe('TypeScript');
  });

  it('detects a React project where identifiable', () => {
    const pkg = {
      name: 'my-react-app',
      dependencies: {
        react: '^18.2.0',
        'react-dom': '^18.2.0'
      }
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg, null, 2));
    fs.writeFileSync(path.join(tempDir, 'yarn.lock'), '');

    const result = detectProject({ cwd: tempDir });

    expect(result.projectName).toBe('my-react-app');
    expect(result.packageManager).toBe('yarn');
    expect(result.framework).toBe('React');
  });

  it('detects a Next.js project with higher priority over React', () => {
    const pkg = {
      name: 'my-next-app',
      dependencies: {
        next: '^14.0.0',
        react: '^18.2.0',
        'react-dom': '^18.2.0'
      }
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg, null, 2));

    const result = detectProject({ cwd: tempDir });

    expect(result.projectName).toBe('my-next-app');
    expect(result.framework).toBe('Next.js');
  });

  it('detects package manager from packageManager field in package.json', () => {
    const pkg = {
      name: 'pm-field-app',
      packageManager: 'pnpm@9.1.0'
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkg, null, 2));

    const result = detectProject({ cwd: tempDir });

    expect(result.packageManager).toBe('pnpm');
  });

  it('handles a directory without package.json gracefully', () => {
    const result = detectProject({ cwd: tempDir });

    expect(result.packageJsonExists).toBe(false);
    expect(result.projectName).toBe(path.basename(tempDir));
    expect(result.packageManager).toBe('None detected');
    expect(result.language).toBe('Unknown');
    expect(result.framework).toBe('None detected');
    expect(result.details.isMalformedPackageJson).toBe(false);
  });

  it('handles malformed package.json gracefully without crashing', () => {
    // Malformed JSON syntax
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{ "name": "bad-json", ');

    const result = detectProject({ cwd: tempDir });

    expect(result.packageJsonExists).toBe(true);
    expect(result.details.isMalformedPackageJson).toBe(true);
    expect(result.projectName).toBe(path.basename(tempDir));
    expect(result.packageManager).toBe('None detected');
  });

  it('handles non-object package.json (e.g. array or primitive)', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '["not", "an", "object"]');

    const result = detectProject({ cwd: tempDir });

    expect(result.packageJsonExists).toBe(true);
    expect(result.details.isMalformedPackageJson).toBe(true);
    expect(result.projectName).toBe(path.basename(tempDir));
  });
});

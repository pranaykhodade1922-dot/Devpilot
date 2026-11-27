import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../src/scanners/sast/parser.js';
import { ImportTracker } from '../../../src/scanners/sast/import-tracker.js';

describe('SAST Import Tracker (import-tracker.ts)', () => {
  it('tracks ES module named imports and renamed imports', () => {
    const code = `
      import { exec, execSync as runSync } from 'child_process';
      import { spawn } from 'node:child_process';
    `;
    const { sourceFile } = parseSourceCode('src/task.ts', code);
    const tracker = ImportTracker.fromSourceFile(sourceFile);

    expect(tracker.resolveImport('exec')).toEqual({
      canonicalSource: 'child_process',
      exportedName: 'exec'
    });
    expect(tracker.resolveImport('runSync')).toEqual({
      canonicalSource: 'child_process',
      exportedName: 'execSync'
    });
    expect(tracker.resolveImport('spawn')).toEqual({
      canonicalSource: 'child_process',
      exportedName: 'spawn'
    });
    expect(tracker.resolveImport('unrelated')).toBeUndefined();
  });

  it('tracks ES module namespace imports', () => {
    const code = `
      import * as cp from 'node:child_process';
    `;
    const { sourceFile } = parseSourceCode('src/task.ts', code);
    const tracker = ImportTracker.fromSourceFile(sourceFile);

    expect(tracker.isNamespaceImport('cp')).toBe('child_process');
    expect(tracker.isNamespaceImport('other')).toBeUndefined();
  });

  it('tracks CommonJS require destructuring and namespace declarations', () => {
    const code = `
      const { exec, execSync: runSync } = require('child_process');
      const cp = require('node:child_process');
    `;
    const { sourceFile } = parseSourceCode('src/legacy.js', code);
    const tracker = ImportTracker.fromSourceFile(sourceFile);

    expect(tracker.resolveImport('exec')).toEqual({
      canonicalSource: 'child_process',
      exportedName: 'exec'
    });
    expect(tracker.resolveImport('runSync')).toEqual({
      canonicalSource: 'child_process',
      exportedName: 'execSync'
    });
    expect(tracker.isNamespaceImport('cp')).toBe('child_process');
  });

  it('identifies verified DOMPurify imports while rejecting unverified sanitizers', () => {
    const code = `
      import DOMPurify from 'dompurify';
      import { sanitize as sanitizeHtml } from 'isomorphic-dompurify';
      import { sanitize as myFakeSanitize } from './my-helpers.js';
    `;
    const { sourceFile } = parseSourceCode('src/view.tsx', code);
    const tracker = ImportTracker.fromSourceFile(sourceFile);

    expect(tracker.resolveImport('DOMPurify')?.canonicalSource).toBe('dompurify');
    expect(tracker.resolveImport('sanitizeHtml')?.canonicalSource).toBe('isomorphic-dompurify');
    expect(tracker.resolveImport('myFakeSanitize')?.canonicalSource).toBe('./my-helpers.js');
  });
});

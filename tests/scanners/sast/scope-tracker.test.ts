import { describe, it, expect } from 'vitest';
import ts from 'typescript';
import { ScopeTracker } from '../../../src/scanners/sast/scope-tracker.js';

describe('SAST Scope Tracker (scope-tracker.ts)', () => {
  it('manages nested lexical scopes correctly', () => {
    const tracker = new ScopeTracker();
    expect(tracker.isShadowed('eval')).toBe(false);

    tracker.enterScope();
    tracker.declareIdentifier('eval');
    expect(tracker.isShadowed('eval')).toBe(true);
    expect(tracker.isShadowed('other')).toBe(false);

    tracker.enterScope();
    expect(tracker.isShadowed('eval')).toBe(true);

    tracker.exitScope();
    expect(tracker.isShadowed('eval')).toBe(true);

    tracker.exitScope();
    expect(tracker.isShadowed('eval')).toBe(false);
  });

  it('registers declarations from destructured bindings and parameters', () => {
    const tracker = new ScopeTracker();
    const source = ts.createSourceFile(
      'test.ts',
      `
      const { a, b: c, d: [e, f] } = options;
      function test({ g, h }: any) {}
      class MyClass {}
      `,
      ts.ScriptTarget.Latest,
      true
    );

    function visit(node: ts.Node) {
      tracker.registerDeclarations(node);
      ts.forEachChild(node, visit);
    }
    visit(source);

    expect(tracker.isShadowed('a')).toBe(true);
    expect(tracker.isShadowed('c')).toBe(true);
    expect(tracker.isShadowed('e')).toBe(true);
    expect(tracker.isShadowed('f')).toBe(true);
    expect(tracker.isShadowed('g')).toBe(true);
    expect(tracker.isShadowed('h')).toBe(true);
    expect(tracker.isShadowed('MyClass')).toBe(true);
    expect(tracker.isShadowed('nonexistent')).toBe(false);
  });
});

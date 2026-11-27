import { describe, it, expect } from 'vitest';
import { parseSourceCode, getScriptKindForPath } from '../../../src/scanners/sast/parser.js';
import ts from 'typescript';

describe('SAST Parser (parser.ts)', () => {
  it('correctly maps file extensions to TypeScript ScriptKind', () => {
    expect(getScriptKindForPath('app.ts')).toBe(ts.ScriptKind.TS);
    expect(getScriptKindForPath('Component.tsx')).toBe(ts.ScriptKind.TSX);
    expect(getScriptKindForPath('view.jsx')).toBe(ts.ScriptKind.JSX);
    expect(getScriptKindForPath('server.js')).toBe(ts.ScriptKind.JS);
    expect(getScriptKindForPath('module.mjs')).toBe(ts.ScriptKind.JS);
    expect(getScriptKindForPath('common.cjs')).toBe(ts.ScriptKind.JS);
    expect(getScriptKindForPath('unknown.extension')).toBe(ts.ScriptKind.TSX);
  });

  it('parses valid TypeScript and ES2022+ syntax cleanly', () => {
    const code = `
      interface User { id: string; role?: string; }
      const getUser = async (id: string): Promise<User | null> => {
        const result = await fetch(\`/api/users/\${id}\`);
        return result.json?.() ?? null;
      };
    `;
    const result = parseSourceCode('src/user.ts', code);

    expect(result.hasErrors).toBe(false);
    expect(result.diagnostics.length).toBe(0);
    expect(result.sourceFile).toBeDefined();
    expect(result.sourceFile.statements.length).toBe(2);
  });

  it('parses React JSX and TSX syntax cleanly', () => {
    const code = `
      import React from 'react';
      export const Card = ({ title, children }: { title: string; children: React.ReactNode }) => (
        <div className="card">
          <h1>{title}</h1>
          <section>{children}</section>
        </div>
      );
    `;
    const result = parseSourceCode('src/Card.tsx', code);

    expect(result.hasErrors).toBe(false);
    expect(result.sourceFile.statements.length).toBe(2);
  });

  it('captures syntax diagnostics while returning a partial AST for recoverable syntax errors', () => {
    // Malformed code: missing closing brace and parenthesis on function
    const malformedCode = `
      function test() {
        const x = 10;
        console.log(x);
      // missing closing brace
      const y = 20;
    `;
    const result = parseSourceCode('src/malformed.ts', malformedCode);

    expect(result.hasErrors).toBe(true);
    expect(result.diagnostics.length).toBeGreaterThan(0);
    // Crucial: AST is partially recovered and accessible for scanning valid statements
    expect(result.sourceFile).toBeDefined();
    expect(result.sourceFile.statements.length).toBeGreaterThan(0);
  });
});

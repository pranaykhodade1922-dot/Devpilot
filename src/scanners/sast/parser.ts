import ts from 'typescript';
import path from 'node:path';

export interface ParseResult {
  sourceFile: ts.SourceFile;
  hasErrors: boolean;
  diagnostics: string[];
}

/**
 * Maps a file extension to the corresponding ts.ScriptKind.
 */
export function getScriptKindForPath(filePath: string): ts.ScriptKind {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.ts':
      return ts.ScriptKind.TS;
    case '.tsx':
      return ts.ScriptKind.TSX;
    case '.jsx':
      return ts.ScriptKind.JSX;
    case '.js':
    case '.mjs':
    case '.cjs':
      return ts.ScriptKind.JS;
    default:
      return ts.ScriptKind.TSX; // TSX covers most modern JS/TS/JSX constructs safely
  }
}

/**
 * Safely parses source code into a TypeScript SourceFile AST.
 *
 * Requirements:
 * - Never executes or evaluates code.
 * - Captures syntax diagnostics without throwing.
 * - Returns the partial AST even if recoverable syntax errors exist.
 */
export function parseSourceCode(filePath: string, content: string): ParseResult {
  const scriptKind = getScriptKindForPath(filePath);

  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    scriptKind
  );

  const parseDiagnostics: ts.Diagnostic[] =
    (sourceFile as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics ?? [];
  const hasErrors = parseDiagnostics.length > 0;

  const diagnostics = parseDiagnostics.map((d: ts.Diagnostic) => {
    if (typeof d.messageText === 'string') {
      return d.messageText;
    }
    return d.messageText.messageText;
  });

  return {
    sourceFile,
    hasErrors,
    diagnostics
  };
}

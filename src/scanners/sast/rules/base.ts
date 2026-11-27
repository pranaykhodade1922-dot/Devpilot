import ts from 'typescript';

/**
 * Checks whether an expression is a compile-time constant string literal
 * (either a standard string literal or a template literal without substitutions).
 */
export function isStaticString(expr: ts.Expression): boolean {
  return ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr);
}

/**
 * Extracts a concise single-line code snippet for evidence reporting.
 */
export function extractNodeSnippet(node: ts.Node, sourceFile: ts.SourceFile): string {
  const text = node.getText(sourceFile).trim();
  const firstLine = text.split(/\r?\n/)[0] ?? text;
  if (firstLine.length > 120) {
    return firstLine.slice(0, 117) + '...';
  }
  return firstLine;
}

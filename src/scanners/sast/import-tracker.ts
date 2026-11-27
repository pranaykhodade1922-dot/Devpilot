import ts from 'typescript';

export interface ResolvedImport {
  canonicalSource: string;
  exportedName: string;
}

export class ImportTracker {
  // Maps local identifier name -> canonical source and exported name
  private namedBindings = new Map<string, ResolvedImport>();
  // Maps namespace identifier name -> canonical source (e.g. 'cp' -> 'child_process')
  private namespaceBindings = new Map<string, string>();

  /**
   * Scans a SourceFile and extracts all ES module and CommonJS require bindings.
   */
  public static fromSourceFile(sourceFile: ts.SourceFile): ImportTracker {
    const tracker = new ImportTracker();
    tracker.collect(sourceFile);
    return tracker;
  }

  private collect(sourceFile: ts.SourceFile): void {
    for (const statement of sourceFile.statements) {
      // 1. ES Module Import Declarations
      if (ts.isImportDeclaration(statement)) {
        this.collectImportDeclaration(statement);
      }
      // 2. CommonJS require variable statements
      else if (ts.isVariableStatement(statement)) {
        this.collectVariableStatement(statement);
      }
    }
  }

  private normalizeSource(rawSource: string): string {
    const cleaned = rawSource.replace(/^['"]|['"]$/g, '');
    if (cleaned.startsWith('node:')) {
      return cleaned.slice(5); // normalize 'node:child_process' -> 'child_process'
    }
    return cleaned;
  }

  private collectImportDeclaration(importDecl: ts.ImportDeclaration): void {
    if (!importDecl.moduleSpecifier || !ts.isStringLiteral(importDecl.moduleSpecifier)) {
      return;
    }

    const source = this.normalizeSource(importDecl.moduleSpecifier.text);
    const importClause = importDecl.importClause;
    if (!importClause) return;

    // Default import: import DOMPurify from 'dompurify'
    if (importClause.name) {
      this.namedBindings.set(importClause.name.text, {
        canonicalSource: source,
        exportedName: 'default'
      });
    }

    // Named or Namespace imports
    const namedBindings = importClause.namedBindings;
    if (namedBindings) {
      if (ts.isNamespaceImport(namedBindings)) {
        // import * as cp from 'child_process'
        this.namespaceBindings.set(namedBindings.name.text, source);
      } else if (ts.isNamedImports(namedBindings)) {
        // import { exec as runCmd, execSync } from 'child_process'
        for (const specifier of namedBindings.elements) {
          const localName = specifier.name.text;
          const exportedName = specifier.propertyName ? specifier.propertyName.text : localName;
          this.namedBindings.set(localName, {
            canonicalSource: source,
            exportedName
          });
        }
      }
    }
  }

  private collectVariableStatement(varStmt: ts.VariableStatement): void {
    for (const decl of varStmt.declarationList.declarations) {
      if (!decl.initializer || !ts.isCallExpression(decl.initializer)) {
        continue;
      }

      const call = decl.initializer;
      if (!ts.isIdentifier(call.expression) || call.expression.text !== 'require') {
        continue;
      }

      const arg = call.arguments[0];
      if (!arg || !ts.isStringLiteral(arg)) {
        continue;
      }

      const source = this.normalizeSource(arg.text);

      // const cp = require('child_process')
      if (ts.isIdentifier(decl.name)) {
        this.namespaceBindings.set(decl.name.text, source);
      }
      // const { exec, execSync: runSync } = require('child_process')
      else if (ts.isObjectBindingPattern(decl.name)) {
        for (const elem of decl.name.elements) {
          if (ts.isIdentifier(elem.name)) {
            const localName = elem.name.text;
            const exportedName =
              elem.propertyName && ts.isIdentifier(elem.propertyName)
                ? elem.propertyName.text
                : localName;
            this.namedBindings.set(localName, {
              canonicalSource: source,
              exportedName
            });
          }
        }
      }
    }
  }

  /**
   * Resolves a local identifier to its imported module source and export name.
   */
  public resolveImport(identifierName: string): ResolvedImport | undefined {
    return this.namedBindings.get(identifierName);
  }

  /**
   * Checks if an identifier is a namespace import (e.g. `cp` from `import * as cp from 'child_process'`).
   */
  public isNamespaceImport(identifierName: string): string | undefined {
    return this.namespaceBindings.get(identifierName);
  }

  /**
   * Checks whether a call expression is a verified DOMPurify.sanitize() call.
   */
  public isVerifiedDomPurify(expr: ts.Expression): boolean {
    if (!ts.isCallExpression(expr)) {
      return false;
    }

    // Call shape 1: DOMPurify.sanitize(...)
    if (ts.isPropertyAccessExpression(expr.expression)) {
      const obj = expr.expression.expression;
      const prop = expr.expression.name;

      if (ts.isIdentifier(obj) && prop.text === 'sanitize') {
        const resolved = this.namedBindings.get(obj.text);
        if (
          resolved &&
          (resolved.canonicalSource === 'dompurify' || resolved.canonicalSource === 'isomorphic-dompurify')
        ) {
          return true;
        }

        const namespaceSource = this.namespaceBindings.get(obj.text);
        if (
          namespaceSource === 'dompurify' ||
          namespaceSource === 'isomorphic-dompurify'
        ) {
          return true;
        }
      }
    }

    // Call shape 2: sanitize(...) where sanitize was imported from dompurify
    if (ts.isIdentifier(expr.expression)) {
      const resolved = this.namedBindings.get(expr.expression.text);
      if (
        resolved &&
        (resolved.canonicalSource === 'dompurify' || resolved.canonicalSource === 'isomorphic-dompurify') &&
        resolved.exportedName === 'sanitize'
      ) {
        return true;
      }
    }

    return false;
  }
}

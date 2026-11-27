import ts from 'typescript';

function extractIdentifiersFromBinding(bindingName: ts.BindingName): string[] {
  if (ts.isIdentifier(bindingName)) {
    return [bindingName.text];
  }
  const names: string[] = [];
  for (const element of bindingName.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...extractIdentifiersFromBinding(element.name));
  }
  return names;
}

export class ScopeTracker {
  private scopeStack: Set<string>[] = [new Set()];

  public enterScope(): void {
    this.scopeStack.push(new Set());
  }

  public exitScope(): void {
    if (this.scopeStack.length > 1) {
      this.scopeStack.pop();
    }
  }

  public declareIdentifier(name: string): void {
    const currentScope = this.scopeStack[this.scopeStack.length - 1];
    if (currentScope) {
      currentScope.add(name);
    }
  }

  public declareInParentScope(name: string): void {
    const parentScope =
      this.scopeStack.length > 1
        ? this.scopeStack[this.scopeStack.length - 2]
        : this.scopeStack[0];
    if (parentScope) {
      parentScope.add(name);
    }
  }

  public isShadowed(name: string): boolean {
    for (let i = this.scopeStack.length - 1; i >= 0; i--) {
      const scope = this.scopeStack[i];
      if (scope && scope.has(name)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Examines a node to see if it introduces declarations into the current scope.
   */
  public registerDeclarations(node: ts.Node): void {
    if (ts.isVariableDeclaration(node)) {
      for (const id of extractIdentifiersFromBinding(node.name)) {
        this.declareIdentifier(id);
      }
    } else if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isConstructorDeclaration(node)
    ) {
      for (const param of node.parameters) {
        for (const id of extractIdentifiersFromBinding(param.name)) {
          this.declareIdentifier(id);
        }
      }
      if (ts.isFunctionDeclaration(node) && node.name && ts.isIdentifier(node.name)) {
        this.declareIdentifier(node.name.text);
        this.declareInParentScope(node.name.text);
      } else if (ts.isFunctionExpression(node) && node.name && ts.isIdentifier(node.name)) {
        this.declareIdentifier(node.name.text);
      }
    } else if (ts.isClassDeclaration(node) && node.name && ts.isIdentifier(node.name)) {
      this.declareIdentifier(node.name.text);
    } else if (ts.isCatchClause(node) && node.variableDeclaration) {
      for (const id of extractIdentifiersFromBinding(node.variableDeclaration.name)) {
        this.declareIdentifier(id);
      }
    } else if (ts.isParameter(node)) {
      for (const id of extractIdentifiersFromBinding(node.name)) {
        this.declareIdentifier(id);
      }
    }
  }
}

import ts from 'typescript';
import type { SastRule, SastRuleContext, SastFindingCandidate } from '../types.js';
import { isStaticString, extractNodeSnippet } from './base.js';

export const RULE_SEC_SAST_COMMAND_INJECTION: SastRule = {
  id: 'SEC-SAST-COMMAND-INJECTION',
  name: 'Command Injection via child_process.exec()',
  category: 'command-injection',
  severity: 'CRITICAL',
  confidence: 'MEDIUM',
  cwe: ['CWE-78'],
  owasp: ['A03:2021-Injection'],
  description:
    'Invoking child_process.exec() or execSync() with dynamic arguments executes a command inside a system shell, exposing the host to OS command injection if input contains untrusted values.',
  remediation:
    'Avoid shell execution. Use child_process.execFile() or child_process.spawn() with arguments passed separately as an array, avoid setting shell: true, and strictly validate or allowlist inputs.',
  check(ctx: SastRuleContext): SastFindingCandidate[] | null {
    const { node, sourceFile, resolveImport, isNamespaceImport } = ctx;

    if (!ts.isCallExpression(node)) {
      return null;
    }

    const expr = node.expression;
    let isChildProcessExec = false;

    // 1. Direct call on imported function: exec(...) or execSync(...) or renamed runCmd(...)
    if (ts.isIdentifier(expr)) {
      const resolved = resolveImport(expr.text);
      if (
        resolved &&
        resolved.canonicalSource === 'child_process' &&
        (resolved.exportedName === 'exec' || resolved.exportedName === 'execSync')
      ) {
        isChildProcessExec = true;
      }
    }
    // 2. Property access: cp.exec(...) or cp.execSync(...)
    else if (ts.isPropertyAccessExpression(expr)) {
      const prop = expr.name.text;
      if (prop === 'exec' || prop === 'execSync') {
        const obj = expr.expression;
        if (ts.isIdentifier(obj)) {
          // Check namespace import: import * as cp from 'child_process' or const cp = require('child_process')
          const nsSource = isNamespaceImport(obj.text);
          if (nsSource === 'child_process') {
            isChildProcessExec = true;
          }

          // Check if object itself is direct child_process module identifier
          if (obj.text === 'child_process') {
            isChildProcessExec = true;
          }
        }
      }
    }

    if (!isChildProcessExec) {
      return null;
    }

    // Inspect first argument (the command string)
    const firstArg = node.arguments[0];
    if (!firstArg) {
      return null;
    }

    const isStatic = isStaticString(firstArg);

    return [
      {
        node,
        severity: isStatic ? 'LOW' : 'CRITICAL',
        confidence: isStatic ? 'HIGH' : 'MEDIUM',
        evidence: extractNodeSnippet(node, sourceFile),
        notes: isStatic
          ? 'child_process.exec() called with compile-time static command. Consider execFile() for robustness.'
          : 'Dynamic command argument passed to child_process.exec(). Risk of arbitrary command execution if input is untrusted.'
      }
    ];
  }
};

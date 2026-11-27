import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../../src/scanners/sast/parser.js';
import { analyzeSourceFile } from '../../../../src/scanners/sast/analyzer.js';
import { RULE_SEC_SAST_EVAL } from '../../../../src/scanners/sast/rules/eval.js';

describe('SAST Rule: SEC-SAST-EVAL', () => {
  it('detects global eval() with dynamic expression as CRITICAL', () => {
    const code = `
      function executeUserCode(userInput: string) {
        return eval(userInput);
      }
    `;
    const { sourceFile } = parseSourceCode('src/eval.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/eval.ts',
      relPath: 'src/eval.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_EVAL]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('SEC-SAST-EVAL');
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[0]?.confidence).toBe('HIGH');
    expect(findings[0]?.location?.line).toBe(3);
    expect(findings[0]?.evidence).toContain('eval(userInput)');
  });

  it('detects global eval() with compile-time static string as MODERATE', () => {
    const code = `
      const constantMath = eval("1 + 2");
    `;
    const { sourceFile } = parseSourceCode('src/eval.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/eval.ts',
      relPath: 'src/eval.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_EVAL]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('MODERATE');
    expect(findings[0]?.evidence).toContain('eval("1 + 2")');
  });

  it('detects window.eval() and globalThis.eval() calls', () => {
    const code = `
      const a = window.eval(payloadA);
      const b = globalThis.eval(payloadB);
    `;
    const { sourceFile } = parseSourceCode('src/global.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/global.ts',
      relPath: 'src/global.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_EVAL]
    });

    expect(findings.length).toBe(2);
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[1]?.severity).toBe('CRITICAL');
  });

  it('detects Function constructor with dynamic and static arguments', () => {
    const code = `
      const dynamicFn = new Function('a', 'b', userScript);
      const staticFn = Function('return 42;');
    `;
    const { sourceFile } = parseSourceCode('src/fn.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/fn.ts',
      relPath: 'src/fn.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_EVAL]
    });

    expect(findings.length).toBe(2);
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[1]?.severity).toBe('MODERATE');
  });

  it('does NOT flag unrelated object methods or lexically shadowed eval identifiers', () => {
    const code = `
      class MathEvaluator {
        eval(expr: string) { return expr.length; }
      }
      const calc = new MathEvaluator();
      const res = calc.eval('1 + 1'); // Object method, not global eval

      function customEvaluator(eval: any) {
        eval.run(); // Parameter named eval shadows global
      }
    `;
    const { sourceFile } = parseSourceCode('src/safe.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/safe.ts',
      relPath: 'src/safe.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_EVAL]
    });

    expect(findings.length).toBe(0);
  });

  it('does NOT flag when eval or Function is locally shadowed by parameters or variables', () => {
    const code = `
      // Destructured parameter shadowing eval
      function handler({ eval }: { eval: (s: string) => void }) {
        eval('destructured');
      }

      // Local variable shadowing Function
      function customFactory() {
        const Function = (script: string) => script;
        Function('console.log(1)');
      }

      // Function declaration shadowing eval
      function eval(code: string) {
        return code.trim();
      }
      eval('test');
    `;
    const { sourceFile } = parseSourceCode('src/shadowed.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/shadowed.ts',
      relPath: 'src/shadowed.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_EVAL]
    });

    expect(findings.length).toBe(0);
  });
});

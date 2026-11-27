import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../../src/scanners/sast/parser.js';
import { analyzeSourceFile } from '../../../../src/scanners/sast/analyzer.js';
import { RULE_SEC_SAST_INNERHTML } from '../../../../src/scanners/sast/rules/dom-xss.js';

describe('SAST Rule: SEC-SAST-INNERHTML', () => {
  it('detects dynamic assignment to element.innerHTML as HIGH severity', () => {
    const code = `
      function renderUserComment(element: HTMLElement, userHtml: string) {
        element.innerHTML = '<div>' + userHtml + '</div>';
      }
    `;
    const { sourceFile } = parseSourceCode('src/render.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/render.ts',
      relPath: 'src/render.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INNERHTML]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('SEC-SAST-INNERHTML');
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.confidence).toBe('HIGH');
    expect(findings[0]?.cwe).toContain('CWE-79');
    expect(findings[0]?.evidence).toContain("element.innerHTML = '<div>' + userHtml + '</div>'");
  });

  it('detects dynamic element.outerHTML and element.insertAdjacentHTML', () => {
    const code = `
      function updateCard(card: HTMLElement, snippet: string) {
        card.outerHTML = \`<section>\${snippet}</section>\`;
        card.insertAdjacentHTML('beforeend', snippet);
      }
    `;
    const { sourceFile } = parseSourceCode('src/card.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/card.ts',
      relPath: 'src/card.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INNERHTML]
    });

    expect(findings.length).toBe(2);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[1]?.severity).toBe('HIGH');
  });

  it('suppresses finding when sanitized with verified DOMPurify call', () => {
    const code = `
      import DOMPurify from 'dompurify';
      function renderSafe(element: HTMLElement, rawHtml: string) {
        element.innerHTML = DOMPurify.sanitize(rawHtml);
        element.insertAdjacentHTML('afterbegin', DOMPurify.sanitize(rawHtml));
      }
    `;
    const { sourceFile } = parseSourceCode('src/clean.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/clean.ts',
      relPath: 'src/clean.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INNERHTML]
    });

    expect(findings.length).toBe(0);
  });

  it('does NOT suppress finding when unverified custom sanitizer is used', () => {
    const code = `
      import { sanitize } from './my-sanitizer.js';
      function render(el: HTMLElement, data: string) {
        el.innerHTML = sanitize(data);
      }
    `;
    const { sourceFile } = parseSourceCode('src/custom.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/custom.ts',
      relPath: 'src/custom.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INNERHTML]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('HIGH');
  });

  it('does NOT flag clearing elements with empty string (el.innerHTML = "")', () => {
    const code = `
      function clearContainer(container: HTMLElement) {
        container.innerHTML = '';
        container.outerHTML = "";
      }
    `;
    const { sourceFile } = parseSourceCode('src/clear.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/clear.ts',
      relPath: 'src/clear.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INNERHTML]
    });

    expect(findings.length).toBe(0);
  });

  it('reports non-empty compile-time static string with LOW severity', () => {
    const code = `
      function showSpinner(target: HTMLElement) {
        target.innerHTML = '<span class="spinner">Loading...</span>';
      }
    `;
    const { sourceFile } = parseSourceCode('src/spinner.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/spinner.ts',
      relPath: 'src/spinner.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INNERHTML]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('LOW');
  });

  it('does NOT flag unrelated object properties named innerHTML', () => {
    const code = `
      const config = {
        innerHTML: 'arbitrary configuration'
      };
      const options = { outerHTML: true };
    `;
    const { sourceFile } = parseSourceCode('src/options.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/options.ts',
      relPath: 'src/options.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INNERHTML]
    });

    expect(findings.length).toBe(0);
  });
});

import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../../src/scanners/sast/parser.js';
import { analyzeSourceFile } from '../../../../src/scanners/sast/analyzer.js';
import { RULE_SEC_SAST_REACT_DANGEROUS_HTML } from '../../../../src/scanners/sast/rules/react-danger.js';

describe('SAST Rule: SEC-SAST-REACT-DANGEROUS-HTML', () => {
  it('detects dangerouslySetInnerHTML with dynamic __html value as HIGH severity', () => {
    const code = `
      import React from 'react';
      export function CommentBody({ rawComment }: { rawComment: string }) {
        return <div dangerouslySetInnerHTML={{ __html: rawComment }} />;
      }
    `;
    const { sourceFile } = parseSourceCode('src/Comment.tsx', code);
    const findings = analyzeSourceFile({
      filePath: 'src/Comment.tsx',
      relPath: 'src/Comment.tsx',
      sourceFile,
      rules: [RULE_SEC_SAST_REACT_DANGEROUS_HTML]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('SEC-SAST-REACT-DANGEROUS-HTML');
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.confidence).toBe('HIGH');
    expect(findings[0]?.location?.line).toBe(4);
    expect(findings[0]?.evidence).toContain('dangerouslySetInnerHTML={{ __html: rawComment }}');
  });

  it('suppresses finding when __html is sanitized with verified DOMPurify import', () => {
    const code = `
      import React from 'react';
      import DOMPurify from 'dompurify';

      export function CleanPost({ postHtml }: { postHtml: string }) {
        return <article dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(postHtml) }} />;
      }
    `;
    const { sourceFile } = parseSourceCode('src/Post.tsx', code);
    const findings = analyzeSourceFile({
      filePath: 'src/Post.tsx',
      relPath: 'src/Post.tsx',
      sourceFile,
      rules: [RULE_SEC_SAST_REACT_DANGEROUS_HTML]
    });

    expect(findings.length).toBe(0);
  });

  it('suppresses finding when using verified named sanitize import from isomorphic-dompurify', () => {
    const code = `
      import React from 'react';
      import { sanitize } from 'isomorphic-dompurify';

      export function Article({ content }: { content: string }) {
        return <section dangerouslySetInnerHTML={{ __html: sanitize(content) }} />;
      }
    `;
    const { sourceFile } = parseSourceCode('src/Article.tsx', code);
    const findings = analyzeSourceFile({
      filePath: 'src/Article.tsx',
      relPath: 'src/Article.tsx',
      sourceFile,
      rules: [RULE_SEC_SAST_REACT_DANGEROUS_HTML]
    });

    expect(findings.length).toBe(0);
  });

  it('does NOT suppress finding when unverified custom sanitizer is used', () => {
    const code = `
      import React from 'react';
      import { sanitize } from './my-custom-sanitizer.js';

      export function RiskyComponent({ text }: { text: string }) {
        // Arbitrary functions named sanitize are NOT trusted
        return <div dangerouslySetInnerHTML={{ __html: sanitize(text) }} />;
      }
    `;
    const { sourceFile } = parseSourceCode('src/Risky.tsx', code);
    const findings = analyzeSourceFile({
      filePath: 'src/Risky.tsx',
      relPath: 'src/Risky.tsx',
      sourceFile,
      rules: [RULE_SEC_SAST_REACT_DANGEROUS_HTML]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('HIGH');
  });

  it('reports static compile-time string literal with LOW severity', () => {
    const code = `
      import React from 'react';
      export function Icon() {
        return <span dangerouslySetInnerHTML={{ __html: '<svg><circle r="10"/></svg>' }} />;
      }
    `;
    const { sourceFile } = parseSourceCode('src/Icon.tsx', code);
    const findings = analyzeSourceFile({
      filePath: 'src/Icon.tsx',
      relPath: 'src/Icon.tsx',
      sourceFile,
      rules: [RULE_SEC_SAST_REACT_DANGEROUS_HTML]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('LOW');
  });

  it('does NOT suppress finding when DOMPurify is imported but not used on the assigned __html value', () => {
    const code = `
      import React from 'react';
      import DOMPurify from 'dompurify';

      export function UnsafeWrapper({ rawSnippet }: { rawSnippet: string }) {
        // DOMPurify is imported in this file, but NOT used on rawSnippet here
        return <div dangerouslySetInnerHTML={{ __html: rawSnippet }} />;
      }
    `;
    const { sourceFile } = parseSourceCode('src/UnsafeWrapper.tsx', code);
    const findings = analyzeSourceFile({
      filePath: 'src/UnsafeWrapper.tsx',
      relPath: 'src/UnsafeWrapper.tsx',
      sourceFile,
      rules: [RULE_SEC_SAST_REACT_DANGEROUS_HTML]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('HIGH');
  });
});

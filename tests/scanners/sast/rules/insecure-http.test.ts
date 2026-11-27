import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../../src/scanners/sast/parser.js';
import { analyzeSourceFile } from '../../../../src/scanners/sast/analyzer.js';
import { RULE_SEC_SAST_INSECURE_HTTP } from '../../../../src/scanners/sast/rules/insecure-http.js';

describe('SAST Rule: SEC-SAST-INSECURE-HTTP', () => {
  it('detects unencrypted HTTP URL in fetch() as MODERATE severity', () => {
    const code = `
      async function syncData() {
        return fetch('http://api.production-service.com/v1/sync');
      }
    `;
    const { sourceFile } = parseSourceCode('src/api.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/api.ts',
      relPath: 'src/api.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INSECURE_HTTP]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('SEC-SAST-INSECURE-HTTP');
    expect(findings[0]?.severity).toBe('MODERATE');
    expect(findings[0]?.confidence).toBe('HIGH');
    expect(findings[0]?.cwe).toContain('CWE-319');
    expect(findings[0]?.evidence).toContain("fetch('http://api.production-service.com/v1/sync')");
  });

  it('detects unencrypted HTTP in axios.get() and axios.post()', () => {
    const code = `
      import axios from 'axios';
      async function callApis(token: string) {
        await axios.get('http://remote-backend.net/users');
        await axios.post('http://remote-backend.net/login', { token });
      }
    `;
    const { sourceFile } = parseSourceCode('src/axios.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/axios.ts',
      relPath: 'src/axios.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INSECURE_HTTP]
    });

    expect(findings.length).toBe(2);
    expect(findings[0]?.severity).toBe('MODERATE');
    expect(findings[1]?.severity).toBe('MODERATE');
  });

  it('detects unencrypted WebSocket in new WebSocket(ws://...)', () => {
    const code = `
      function connectStream() {
        return new WebSocket('ws://stream.live-data.io/feed');
      }
    `;
    const { sourceFile } = parseSourceCode('src/ws.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/ws.ts',
      relPath: 'src/ws.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INSECURE_HTTP]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.evidence).toContain("new WebSocket('ws://stream.live-data.io/feed')");
  });

  it('does NOT flag secure HTTPS or secure WebSockets (wss://)', () => {
    const code = `
      async function safeNetworkCalls() {
        await fetch('https://api.secure-service.com/v1/users');
        new WebSocket('wss://stream.secure-service.com/feed');
      }
    `;
    const { sourceFile } = parseSourceCode('src/safe-net.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/safe-net.ts',
      relPath: 'src/safe-net.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INSECURE_HTTP]
    });

    expect(findings.length).toBe(0);
  });

  it('does NOT flag local development URLs (localhost, 127.0.0.1, [::1])', () => {
    const code = `
      async function localDev() {
        await fetch('http://localhost:3000/api/dev');
        await fetch('http://127.0.0.1:8080/health');
        new WebSocket('ws://localhost:4000/socket');
      }
    `;
    const { sourceFile } = parseSourceCode('src/dev.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/dev.ts',
      relPath: 'src/dev.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INSECURE_HTTP]
    });

    expect(findings.length).toBe(0);
  });

  it('does NOT flag non-network strings containing http:// (e.g. XML namespaces or logs)', () => {
    const code = `
      const schema = 'http://www.w3.org/2000/svg';
      console.log('Documentation: http://example.com/docs');
      const info = { url: 'http://example.com' };
    `;
    const { sourceFile } = parseSourceCode('src/log.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/log.ts',
      relPath: 'src/log.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_INSECURE_HTTP]
    });

    expect(findings.length).toBe(0);
  });
});

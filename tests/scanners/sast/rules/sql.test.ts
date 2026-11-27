import { describe, it, expect } from 'vitest';
import { parseSourceCode } from '../../../../src/scanners/sast/parser.js';
import { analyzeSourceFile } from '../../../../src/scanners/sast/analyzer.js';
import { RULE_SEC_SAST_SQL_INJECTION } from '../../../../src/scanners/sast/rules/sql.js';

describe('SAST Rule: SEC-SAST-SQL-INJECTION', () => {
  it('detects string concatenation in database query as CRITICAL', () => {
    const code = `
      import { Client } from 'pg';
      const client = new Client();
      async function getUser(userId: string) {
        return client.query('SELECT * FROM users WHERE id = ' + userId);
      }
    `;
    const { sourceFile } = parseSourceCode('src/db.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/db.ts',
      relPath: 'src/db.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_SQL_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe('SEC-SAST-SQL-INJECTION');
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[0]?.confidence).toBe('HIGH');
    expect(findings[0]?.cwe).toContain('CWE-89');
    expect(findings[0]?.evidence).toContain("client.query('SELECT * FROM users WHERE id = ' + userId)");
  });

  it('detects template literal with dynamic interpolation in db.query()', () => {
    const code = `
      import mysql from 'mysql2/promise';
      async function findByEmail(db: any, email: string) {
        return db.query(\`SELECT * FROM accounts WHERE email = '\${email}'\`);
      }
    `;
    const { sourceFile } = parseSourceCode('src/account.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/account.ts',
      relPath: 'src/account.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_SQL_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[0]?.confidence).toBe('HIGH');
  });

  it('detects Prisma $queryRawUnsafe with dynamic query as CRITICAL', () => {
    const code = `
      import { PrismaClient } from '@prisma/client';
      const prisma = new PrismaClient();
      async function search(term: string) {
        return prisma.$queryRawUnsafe('SELECT * FROM items WHERE name LIKE ' + term);
      }
    `;
    const { sourceFile } = parseSourceCode('src/items.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/items.ts',
      relPath: 'src/items.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_SQL_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('CRITICAL');
    expect(findings[0]?.evidence).toContain('prisma.$queryRawUnsafe');
  });

  it('reports Prisma $queryRawUnsafe with compile-time static string as LOW severity', () => {
    const code = `
      import { PrismaClient } from '@prisma/client';
      const prisma = new PrismaClient();
      async function healthCheck() {
        return prisma.$queryRawUnsafe('SELECT 1');
      }
    `;
    const { sourceFile } = parseSourceCode('src/health.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/health.ts',
      relPath: 'src/health.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_SQL_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('LOW');
  });

  it('detects SQL injection in SQLite / better-sqlite3 db.prepare() dynamic queries', () => {
    const code = `
      import Database from 'better-sqlite3';
      const db = new Database('app.db');
      function findRow(val: string) {
        return db.prepare('SELECT * FROM table WHERE col = ' + val).get();
      }
    `;
    const { sourceFile } = parseSourceCode('src/sqlite.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/sqlite.ts',
      relPath: 'src/sqlite.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_SQL_INJECTION]
    });

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe('CRITICAL');
  });

  it('does NOT flag properly parameterized queries in SQLite, PostgreSQL, or MySQL', () => {
    const code = `
      import { Client } from 'pg';
      import Database from 'better-sqlite3';

      const client = new Client();
      const db = new Database('app.db');

      async function safeQueries(id: string, email: string) {
        // Parameterized PostgreSQL queries with $1
        await client.query('SELECT * FROM users WHERE id = $1', [id]);
        await client.query('SELECT * FROM users WHERE email = $1 AND active = $2', [email, true]);

        // Parameterized SQLite queries with ?
        const stmt = db.prepare('SELECT * FROM items WHERE category = ? AND price > ?');
        stmt.all('electronics', 100);
      }
    `;
    const { sourceFile } = parseSourceCode('src/safe.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/safe.ts',
      relPath: 'src/safe.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_SQL_INJECTION]
    });

    expect(findings.length).toBe(0);
  });

  it('does NOT flag non-database query methods (e.g. url.query or search params)', () => {
    const code = `
      const parsedUrl = new URL('https://example.com?query=hello');
      const q = parsedUrl.searchParams.get('query');
      const obj = { query: (filter: string) => filter };
      obj.query('name = test');
    `;
    const { sourceFile } = parseSourceCode('src/non-db.ts', code);
    const findings = analyzeSourceFile({
      filePath: 'src/non-db.ts',
      relPath: 'src/non-db.ts',
      sourceFile,
      rules: [RULE_SEC_SAST_SQL_INJECTION]
    });

    expect(findings.length).toBe(0);
  });
});

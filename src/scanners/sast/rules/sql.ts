import ts from 'typescript';
import type { SastRule, SastRuleContext, SastFindingCandidate } from '../types.js';
import { isStaticString, extractNodeSnippet } from './base.js';

const KNOWN_DB_PACKAGES = new Set([
  'pg',
  'mysql',
  'mysql2',
  'mysql2/promise',
  'sqlite3',
  'better-sqlite3',
  'sequelize',
  'typeorm',
  'knex',
  '@prisma/client',
  'duckdb',
  'mariadb',
  'mssql',
  'oracledb'
]);

const KNOWN_DB_IDENTIFIERS = new Set([
  'db',
  'pool',
  'client',
  'connection',
  'conn',
  'knex',
  'prisma',
  'sequelize',
  'dataSource',
  'entityManager'
]);

const SQL_KEYWORDS_REGEX = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|ALTER|CREATE|TABLE|JOIN|UNION)\b/i;

function isBinaryStringConcat(node: ts.Node): boolean {
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return true;
  }
  return false;
}

function hasSqlKeywords(node: ts.Node, sourceFile: ts.SourceFile): boolean {
  const text = node.getText(sourceFile);
  return SQL_KEYWORDS_REGEX.test(text);
}

export const RULE_SEC_SAST_SQL_INJECTION: SastRule = {
  id: 'SEC-SAST-SQL-INJECTION',
  name: 'SQL Injection in Database Query',
  category: 'sql-injection',
  severity: 'CRITICAL',
  confidence: 'HIGH',
  cwe: ['CWE-89'],
  owasp: ['A03:2021-Injection'],
  description:
    'Passing dynamically concatenated strings or template expressions directly into database query sinks allows attackers to alter SQL logic, potentially leading to unauthorized data disclosure, data corruption, or administrative database takeover.',
  remediation:
    'Use parameterized queries or prepared statements (e.g. db.query("SELECT * FROM users WHERE id = $1", [id])), or an ORM query builder. Avoid string concatenation and raw query methods like $queryRawUnsafe.',
  check(ctx: SastRuleContext): SastFindingCandidate[] | null {
    const { node, sourceFile, resolveImport, isNamespaceImport } = ctx;

    if (!ts.isCallExpression(node)) {
      return null;
    }

    const expr = node.expression;
    let isDbSink = false;
    let isPrismaUnsafe = false;

    // 1. Property access calls: obj.query(...), obj.execute(...), prisma.$queryRawUnsafe(...)
    if (ts.isPropertyAccessExpression(expr)) {
      const methodName = expr.name.text;
      const targetObj = expr.expression;

      if (methodName === '$queryRawUnsafe' || methodName === '$executeRawUnsafe') {
        isDbSink = true;
        isPrismaUnsafe = true;
      } else if (
        methodName === 'query' ||
        methodName === 'execute' ||
        methodName === 'raw' ||
        methodName === 'prepare'
      ) {
        if (ts.isIdentifier(targetObj)) {
          const objName = targetObj.text;
          const resolved = resolveImport(objName);
          const nsSource = isNamespaceImport(objName);

          if (
            (resolved && KNOWN_DB_PACKAGES.has(resolved.canonicalSource)) ||
            (nsSource && KNOWN_DB_PACKAGES.has(nsSource)) ||
            KNOWN_DB_IDENTIFIERS.has(objName)
          ) {
            isDbSink = true;
          }
        } else if (ts.isPropertyAccessExpression(targetObj)) {
          // e.g. this.db.query(...) or ctx.pool.query(...)
          const propName = targetObj.name.text;
          if (KNOWN_DB_IDENTIFIERS.has(propName)) {
            isDbSink = true;
          }
        }
      }
    }
    // 2. Direct function calls: query(...), execute(...), prepare(...)
    else if (ts.isIdentifier(expr)) {
      const resolved = resolveImport(expr.text);
      if (
        resolved &&
        KNOWN_DB_PACKAGES.has(resolved.canonicalSource) &&
        (resolved.exportedName === 'query' ||
          resolved.exportedName === 'execute' ||
          resolved.exportedName === 'raw' ||
          resolved.exportedName === 'prepare')
      ) {
        isDbSink = true;
      }
    }

    if (!isDbSink) {
      return null;
    }

    const firstArg = node.arguments[0];
    if (!firstArg) {
      return null;
    }

    // Prisma $queryRawUnsafe handling
    if (isPrismaUnsafe) {
      const isStatic = isStaticString(firstArg);
      return [
        {
          node,
          severity: isStatic ? 'LOW' : 'CRITICAL',
          confidence: 'HIGH',
          evidence: extractNodeSnippet(node, sourceFile),
          notes: isStatic
            ? 'Prisma $queryRawUnsafe invoked with static string. Prefer type-safe $queryRaw with template tags.'
            : 'Unsafe raw query method $queryRawUnsafe invoked with dynamic query. High risk of SQL injection.'
        }
      ];
    }

    // Static queries (or static parameterized query templates) are SAFE
    if (isStaticString(firstArg)) {
      return null;
    }

    // Dynamic query detection:
    // 1. Template expression with substitutions: `SELECT * FROM users WHERE id = ${id}`
    if (ts.isTemplateExpression(firstArg)) {
      return [
        {
          node,
          severity: 'CRITICAL',
          confidence: 'HIGH',
          evidence: extractNodeSnippet(node, sourceFile),
          notes:
            'Dynamic template literal passed directly to database query sink without parameterization. Risk of SQL injection.'
        }
      ];
    }

    // 2. Binary string concatenation: "SELECT * FROM users WHERE id = " + userId
    if (isBinaryStringConcat(firstArg)) {
      return [
        {
          node,
          severity: 'CRITICAL',
          confidence: 'HIGH',
          evidence: extractNodeSnippet(node, sourceFile),
          notes:
            'Dynamic string concatenation passed directly to database query sink. Risk of SQL injection.'
        }
      ];
    }

    // 3. Dynamic variable passed without parameter array: client.query(userQuery)
    if (node.arguments.length === 1 && hasSqlKeywords(node, sourceFile)) {
      return [
        {
          node,
          severity: 'CRITICAL',
          confidence: 'MEDIUM',
          evidence: extractNodeSnippet(node, sourceFile),
          notes:
            'Dynamic query expression passed to database query method without parameterized values.'
        }
      ];
    }

    return null;
  }
};

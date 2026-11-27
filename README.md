# DevPilot Security

**DevPilot Security** is an open-source developer security toolkit designed to help engineering teams identify, understand, and address application security risks early in the software development lifecycle.

The long-term workflow for DevPilot Security is:

```
SCAN → UNDERSTAND → FIX → VERIFY → MONITOR
```

---

## Getting Started

### The Primary Developer Command: `devpilot scan`

For most development and CI workflows, run the unified security scanner:

```bash
devpilot scan
```

The unified scan command automatically:
1. **Detects the project**: Resolves language, framework, and package manager.
2. **Audits dependencies**: Queries OSV for known vulnerabilities in installed packages.
3. **Scans for secrets**: Analyzes project files locally for hardcoded API keys, tokens, and credentials.
4. **Performs SAST analysis**: Parses JavaScript/TypeScript source code to detect high-risk patterns (SQL injection, XSS, command injection, dynamic evaluation, insecure HTTP, and weak cryptography).
5. **Produces an aggregated report**: Combines and prioritizes all findings across all scanners by severity.

```bash
# Scan a specific directory
devpilot scan ./my-project

# Output machine-readable JSON
devpilot scan --json
```

---

## Combined Scan Report Example

```
 DevPilot Security Report
──────────────────────────────────────────────────────────────────────
Project:               my-app
Project Root:          /path/to/my-app
Language / Tech:       TypeScript (Express)
Package Manager:       npm
Scan Duration:         145ms
──────────────────────────────────────────────────────────────────────
Scanner Status:
  Dependency Scanner:  Completed
  Secret Scanner:      Completed
  SAST Scanner:        Completed
──────────────────────────────────────────────────────────────────────
Total findings:        3
──────────────────────────────────────────────────────────────────────
Findings by Severity:
   CRITICAL  2       HIGH    1     MODERATE  0       LOW     0     UNKNOWN   0
──────────────────────────────────────────────────────────────────────
Findings Details:

1.  CRITICAL   SECRET  .env L4:C20
   Issue:        SEC-AWS-001 — AWS Access Key ID detected in .env
   Evidence:     AWS_ACCESS_KEY_ID="AKI...[REDACTED]...PLE"
   Notes:        Secret value masked: AKI...[REDACTED]...PLE
   Remediation:  Immediately rotate this AWS Access Key in AWS IAM or Secrets Manager.

2.  CRITICAL     SAST  src/db/users.ts:14:12
   Issue:        SEC-SAST-SQL-INJECTION — SQL Injection in Database Query
   Evidence:     client.query('SELECT * FROM users WHERE id = ' + userId)
   Remediation:  Use parameterized queries or prepared statements (e.g. client.query("SELECT * FROM users WHERE id = $1", [id])).

3.    HIGH     DEPENDENCY  axios @0.21.1 (direct)
   Issue:        GHSA-cph5-m8f7-6c5x — Server-Side Request Forgery in axios
   Evidence:     axios@0.21.1 satisfies affected range <0.21.2
   Remediation:  Upgrade axios to 0.21.2 or higher.
   Reference:    https://github.com/advisories/GHSA-cph5-m8f7-6c5x

──────────────────────────────────────────────────────────────────────
ℹ Remediation Guidance: Prioritize CRITICAL and HIGH severities. Revoke any exposed secrets immediately, upgrade vulnerable dependencies, and remediate risky source-code patterns before deploying.
──────────────────────────────────────────────────────────────────────
```

---

## Command Reference

### Main Commands
- **`devpilot scan [path]`**: Recommended primary entry point. Coordinates dependency auditing, secret scanning, and SAST code analysis in a unified run.
- **`devpilot scan [path] --json`**: Outputs complete unified scan results as valid, unstyled JSON.

### Security Commands (Specialized / Advanced)
- **`devpilot security deps [path]`**: Runs only the dependency vulnerability scanner against `package-lock.json` and the OSV database.
- **`devpilot security deps [path] --json`**: Outputs dependency-only scan results as JSON.
- **`devpilot security secrets [path]`**: Runs only the local-first secret scanner against project source files.
- **`devpilot security secrets [path] --json`**: Outputs secret-only scan results as JSON.
- **`devpilot security sast [path]`**: Runs only the static application security testing (SAST) scanner against JavaScript and TypeScript source files.
- **`devpilot security sast [path] --json`**: Outputs SAST-only scan results as JSON.

### Utility Commands
- **`devpilot about`**: Displays project information, founder credits, mission, installed version, and repository links.
- **`devpilot doctor`**: Verifies local environment readiness (Node.js runtime, OS, working directory).
- **`devpilot --version`** (`-v`): Displays installed DevPilot version.
- **`devpilot --help`** (`-h`): Shows organized command reference and practical examples.

---

## About DevPilot Security

DevPilot Security is created by **Pranay Khodade** to provide developers with intuitive, actionable, and local-first security tooling.

### Founder & Creator
- **Founder**: Pranay Khodade
- **Title**: Founder & Creator
- **Project**: DevPilot Security
- **Mission**: Help developers identify, understand, and fix security issues in their projects.
- **Repository**: [https://github.com/pranaykhodade1922-dot/Devpilot](https://github.com/pranaykhodade1922-dot/Devpilot)

To view project and founder details directly in your terminal, run:

```bash
devpilot about
```

Example output:

```text
────────────────────────────────────────────
             DEVPILOT SECURITY
────────────────────────────────────────────

A developer-friendly security toolkit
for modern applications.

CREATED BY
Pranay Khodade
Founder & Creator

PROJECT
Version:       0.1.0
Repository:    https://github.com/pranaykhodade1922-dot/Devpilot
License:       MIT

OUR MISSION
Help developers identify, understand,
and fix security issues in their projects.

────────────────────────────────────────────
       Built for developers, by developers.
────────────────────────────────────────────
```

---

## Detailed Scanner Capabilities

### 1. Dependency Vulnerability Scanner
- **Full Advisory Hydration**: Retrieves detailed advisory records (`GET /v1/vulns/{id}`) with in-memory caching and bounded concurrency.
- **Accurate Semver Range Matching**: Validates installed package versions against advisory `introduced`, `fixed`, `last_affected`, `limit` intervals, and explicit version lists to eliminate false positives.
- **CVSS Scoring & Vector Interpretation**: Evaluates CVSS v3 / v3.1 vector strings and numeric scores to accurately categorize severities into `CRITICAL`, `HIGH`, `MODERATE`, and `LOW`.
- **Intelligent Remediation**: Recommends the safest upgrade path (patch/minor updates within the current major line vs. notifying when breaking major bumps are required).
- **Monorepo & Workspace Filtering**: Automatically ignores local workspace links (`link: true`, `file:`, `workspace:`), ensuring internal proprietary package names are never sent to external APIs.
- **npm Alias Support**: Accurately tracks aliased npm packages (e.g., `"my-react": "npm:react@^18.2.0"`) as direct dependencies.
- **Advisory Deduplication**: Unifies duplicate advisories sharing aliases (CVE, GHSA, OSV) for the same installed dependency.

### 2. Secret Scanner
- **Extensible Detection Rules**: 10 built-in rules detecting AWS access keys & secrets, Google Cloud / Firebase API keys, GitHub tokens (PAT, OAuth, app), GitLab tokens (PAT, pipeline, deploy), Slack tokens & webhooks, Database URIs with credentials (PostgreSQL, MySQL, MongoDB, Redis), RSA/EC/OPENSSH/PGP private keys, generic passwords, and context-supported high-entropy values.
- **Strict In-Memory Masking & Redaction**: Raw secret values are NEVER stored in findings, logs, JSON, or console output. Multi-level redaction masks tokens (e.g. `AKI...[REDACTED]...PLE`) and replaces multiline PEM private-key blocks with line-preserving placeholders (`[REDACTED PRIVATE KEY LINE]`) to maintain accurate line numbering.
- **Safe & Resilient File Crawling**: Respects `.gitignore` (including nested rules, negation patterns, and directory anchors), automatically ignores build artifacts (`node_modules`, `dist`, `build`, `coverage`, `.git`), skips binary files via null-byte inspection (`\0`), and enforces a 2 MB file size limit.
- **Path Containment & Symlink Safety**: Rejects traversal outside the scan root directory and skips symbolic links by default to prevent directory escapes and infinite loops.
- **Honest Skipped Reporting**: Accurately tracks intentionally excluded files (ignored by rule/policy) separately from error-skipped files (I/O or size errors), ensuring unreadable files trigger appropriate non-zero exit codes.

### 3. Static Application Security Testing (SAST)
- **Safe Abstract Syntax Tree (AST) Parsing**: Analyzes JavaScript, TypeScript, JSX, TSX, MJS, and CJS source files using the TypeScript Compiler API without executing scanned project code.
- **Import & Lexical Scope Tracking**: Accurately tracks renamed imports, namespace imports (`import * as cp from 'child_process'`), CommonJS `require()` destructuring, and nested lexical scopes (blocks, functions, parameters, destructuring) to eliminate false positives on shadowed identifiers.
- **Built-in SAST Rules Catalog**:
  1. **`SEC-SAST-EVAL`** (CWE-95, CWE-94, OWASP A03:2021): Flags dynamic string evaluation via global `eval()`, `window.eval()`, `globalThis.eval()`, and the `Function` constructor.
  2. **`SEC-SAST-REACT-DANGEROUS-HTML`** (CWE-79, OWASP A03:2021): Flags dynamic `__html` assignments in React `dangerouslySetInnerHTML`. Recognizes verified sanitizers (`DOMPurify.sanitize()`) and distinguishes static strings.
  3. **`SEC-SAST-COMMAND-INJECTION`** (CWE-78, OWASP A03:2021): Detects dynamic arguments passed to `child_process.exec()` or `execSync()`. Recommends `execFile()` or `spawn()` with separate argument arrays and warns against `shell: true`.
  4. **`SEC-SAST-SQL-INJECTION`** (CWE-89, OWASP A03:2021): Flags string concatenation, dynamic template literals, and Prisma `$queryRawUnsafe()` calls in database query sinks. Parameterized queries (`query("SELECT ... WHERE id = $1", [id])`) and static queries are recognized as safe.
  5. **`SEC-SAST-INNERHTML`** (CWE-79, OWASP A03:2021): Detects unescaped dynamic HTML assigned to `element.innerHTML`, `element.outerHTML`, or `element.insertAdjacentHTML()`. Recognizes verified DOMPurify sanitization.
  6. **`SEC-SAST-INSECURE-HTTP`** (CWE-319, OWASP A02:2021): Detects unencrypted `http://` or `ws://` network endpoints in `fetch()`, `axios`, `XMLHttpRequest`, and `WebSocket`. Excludes local development endpoints (`localhost`, `127.0.0.1`, `[::1]`) and schema namespaces (`w3.org`).
  7. **`SEC-SAST-WEAK-CRYPTO`** (CWE-327, CWE-328, CWE-338, OWASP A02:2021): Flags broken hash algorithms (MD5, SHA-1), deprecated `crypto.createCipher()`, weak ciphers (DES, RC4), and insecure `Math.random()` used in security-sensitive credential or token generation contexts.
- **Fault-Tolerant Scanning**: Recovers gracefully from syntax errors, records diagnostic records, and flags partial scans so projects with parse errors are never falsely reported as clean.
- **Limitations**: Performs AST pattern matching, import resolution, and lexical scope tracking. It does not perform full runtime taint tracking across module boundaries and cannot guarantee complete vulnerability detection.

### 4. Scanner Coverage & Principles
- **Current Coverage**: npm package dependencies (`package-lock.json` v2/v3), project file secrets, and JavaScript/TypeScript SAST.
- **Local-First & Non-Destructive**: DevPilot Security never modifies scanned source files, never alters dependencies, and never transmits secrets or source code over the network.

---

## Code Examples: Unsafe vs. Safe

| Category | Unsafe Code | Safe Code |
| :--- | :--- | :--- |
| **SQL Injection** | `db.query('SELECT * FROM users WHERE id = ' + id)` | `db.query('SELECT * FROM users WHERE id = $1', [id])` |
| **Prisma Queries** | `prisma.$queryRawUnsafe('SELECT * FROM items WHERE id = ' + id)` | `prisma.$queryRaw\`SELECT * FROM items WHERE id = ${id}\`` |
| **DOM XSS** | `el.innerHTML = '<div>' + userComment + '</div>'` | `el.innerHTML = DOMPurify.sanitize(userComment)` |
| **React XSS** | `<div dangerouslySetInnerHTML={{ __html: userHtml }} />` | `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userHtml) }} />` |
| **Command Injection** | `exec('ping -c 1 ' + host)` | `execFile('ping', ['-c', '1', host])` |
| **Code Evaluation** | `eval(userPayload)` | `JSON.parse(userPayload)` |
| **Network Requests** | `fetch('http://api.myservice.com/v1/data')` | `fetch('https://api.myservice.com/v1/data')` |
| **Hashing** | `crypto.createHash('md5').update(data)` | `crypto.createHash('sha256').update(data)` |
| **Tokens / Secrets** | `const token = Math.random().toString(36)` | `const token = crypto.randomBytes(32).toString('hex')` |

---

## CLI Exit Codes

DevPilot Security returns predictable, standardized process exit codes designed for local development and CI/CD pipelines:

| Exit Code | Status | Meaning |
| :---: | :--- | :--- |
| **`0`** | **CLEAN** | Scan completed successfully. No vulnerabilities, secrets, or SAST issues were identified. |
| **`1`** | **VULNERABLE** | Scan completed successfully, but one or more security findings were detected in dependencies, secrets, or source code. |
| **`2`** | **FAILED** | Scan failed or could not complete reliably (e.g., target directory not found, missing lockfile, network unavailable during required dependency scan). |
| **`3`** | **PARTIAL** | Scan completed partially (e.g., files had syntax/parse errors, or files exceeded size limits). Cannot be certified clean. |

---

## CI/CD Pipeline Integration

DevPilot Security can be integrated into GitHub Actions, GitLab CI, or any automated pipeline.

### Example: GitHub Actions Workflow

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run DevPilot Security Audit
        run: npx devpilot security deps
```

### Scripting with Exit Codes in CI

```bash
# Example shell script distinguishing vulnerabilities from infrastructure errors
npx devpilot security deps
STATUS=$?

if [ $STATUS -eq 0 ]; then
  echo "✔ Security check passed! No vulnerabilities."
elif [ $STATUS -eq 1 ]; then
  echo "✖ Security check failed! Vulnerabilities detected in dependencies."
  exit 1
elif [ $STATUS -eq 2 ]; then
  echo "⚠ Infrastructure error: Lockfile missing or scanner failed."
  exit 2
elif [ $STATUS -eq 3 ]; then
  echo "⚠ Partial scan: Upstream advisory service unavailable. Review logs."
  exit 3
fi
```

---

## Partial Scans Explained

In production, security scanners query remote advisory databases like OSV. A network glitch or upstream 404 for a single advisory record should not crash an entire build pipeline, but it **must never be reported as a clean scan**.

When DevPilot Security receives candidate vulnerability IDs from the OSV batch query, but is unable to retrieve the complete advisory record for one or more IDs (e.g. due to individual request timeouts or rate limits):
1. The scanner flags the finding as incomplete (`isIncomplete: true`) and presents the available minimal metadata.
2. The overall scan status is set to **`PARTIAL`**.
3. The process exits with **Exit Code `3`**.
4. Both human terminal output and JSON reports include clear notices indicating that incomplete upstream data prevented full certification.

---

## CVSS Severity Sources & Transparency

DevPilot Security distinguishes between different sources of vulnerability severity ratings rather than conflating them:

- **OSV / Advisory Database (`database_specific`)**: The severity rating explicitly published by the advisory author or database maintainer (e.g., GitHub Security Advisories).
- **Calculated CVSS v3/v3.1 (`calculated_cvss3`)**: Calculated locally from the official CVSS v3.x vector using the FIRST.org v3.1 standard scoring equation.
- **Advisory Score (`explicit_score`)**: A numeric CVSS base score provided directly by the upstream vulnerability record.
- **CVSS v4.0 Handling**: When an advisory specifies a `CVSS:4.0` vector, DevPilot Security preserves the complete v4 vector and qualitative severity from the advisory database without incorrectly computing an artificial score using legacy v3 formulas.
- **Indeterminate (`unknown`)**: When neither an advisory database severity nor a calculable vector is available, the rating is reported as `UNKNOWN` rather than guessing or fabricating severity.

---

## Architecture

```
devpilot/
├── src/
│   ├── cli/
│   │   ├── commands/
│   │   │   ├── doctor.ts               # Environment diagnostic command
│   │   │   ├── scan.ts                 # Unified security scanner command (deps + secrets)
│   │   │   └── security.ts             # Security scanning & exit code handling
│   │   └── index.ts                    # Commander CLI entry point
│   ├── core/
│   │   ├── finding.ts                  # Standardized SecurityFinding interface & severity model
│   │   └── project-detector.ts         # Framework and language detection engine
│   ├── scanners/
│   │   ├── dependency/
│   │   │   ├── types.ts                # Lockfile & OSV client data models
│   │   │   ├── semver-matcher.ts       # Accurate semver range and event interval evaluator
│   │   │   ├── cvss-helper.ts          # FIRST.org CVSS v3.1 vector calculator & scoring
│   │   │   ├── lockfile-parser.ts      # package-lock.json v2/v3 parser (workspaces & aliases)
│   │   │   ├── osv-client.ts           # OSV batch client & advisory hydration with cache
│   │   │   ├── dependency-scanner.ts   # Scanner orchestrator & finding normalizer
│   │   │   └── index.ts                # Scanner exports
│   │   └── secret/
│   │       ├── types.ts                # Secret rules, matches, categories & scan metrics
│   │       ├── entropy.ts              # Shannon entropy computation engine
│   │       ├── masking.ts              # Safe secret masking & multiline PEM block redaction
│   │       ├── rules.ts                # 10 built-in detection rules with false-positive filters
│   │       ├── file-crawler.ts         # Safe recursive crawler with .gitignore & size checks
│   │       ├── secret-scanner.ts       # Secret scanning orchestrator & finding generator
│   │       └── index.ts                # Module exports
│   ├── utils/
│   │   └── version.ts                  # Safe CLI version resolution
│   └── index.ts                        # Library public API exports
├── tests/
│   ├── cli/
│   │   ├── exit-codes.test.ts          # Tests for Exit Codes 0, 1, 2, and 3
│   │   ├── security-secrets.test.ts    # CLI integration tests for devpilot security secrets
│   │   └── unified-scan.test.ts        # CLI integration tests for unified devpilot scan
│   ├── doctor.test.ts                  # Environment diagnostic tests
│   ├── project-detector.test.ts        # Project detection tests
│   └── scanners/
│       ├── dependency/
│       │   ├── semver-matcher.test.ts  # Semver range matching & prerelease tests
│       │   ├── cvss-helper.test.ts     # CVSS vector calculation tests
│       │   ├── lockfile-parser.test.ts # Lockfile parsing, aliases & workspace tests
│       │   ├── osv-client.test.ts      # OSV API client, cache & hydration tests
│       │   └── dependency-scanner.test.ts # End-to-end scanner & deduplication tests
│       └── secret/
│           ├── entropy.test.ts         # Shannon entropy unit tests
│           ├── masking.test.ts         # Redaction & private-key masking unit tests
│           ├── rules.test.ts           # 10 built-in rules & false-positive filter tests
│           ├── file-crawler.test.ts    # Traversal, gitignore & symlink containment tests
│           └── secret-scanner.test.ts  # Secret scanner orchestrator & finding tests
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── .gitignore
└── README.md
```

---

## Prerequisites

- **Node.js**: `>= 18.0.0` (Native `fetch` and ESM required)
- **npm**: `>= 9.0.0`

---

## Development Setup

1. **Install dependencies:**

   ```bash
   npm install
   ```

2. **Run TypeScript typecheck:**

   ```bash
   npm run typecheck
   ```

3. **Run unit tests:**

   ```bash
   npm test
   ```

4. **Build production bundle:**

   ```bash
   npm run build
   ```

---

## Safety & Security Guarantees

- **100% Read-Only**: The scanner never modifies, mutates, or deletes `package.json`, `package-lock.json`, source files, or credentials.
- **Privacy Conscious & Local-First**: Secret scanning is completely local. Discovered secrets are never transmitted externally or sent to any remote API.
- **Strict Redaction**: Raw secret values are never printed in terminal output, logs, errors, or JSON findings. Full multiline private-key payloads are protected.
- **Zero Package Execution**: Never invokes package lifecycle scripts (`postinstall`, etc.) or arbitrary shell commands.
- **Fail-Safe Status**: Network timeouts, missing paths, or corrupted files trigger non-zero exit codes (`2` FAILED or `3` PARTIAL) and are never reported as clean.

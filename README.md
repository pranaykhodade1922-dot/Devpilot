# DevPilot Security

[![npm version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://www.npmjs.com/package/devpilot-security)
[![CI](https://github.com/pranaykhodade1922-dot/Devpilot/actions/workflows/ci.yml/badge.svg)](https://github.com/pranaykhodade1922-dot/Devpilot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)

**Developer security toolkit for modern applications.**

**DevPilot Security** (`devpilot`) is a fast, local-first, developer-friendly command-line toolkit designed to help engineering teams identify, understand, and remediate application security risks early in the software development lifecycle.

The core philosophy of DevPilot Security is:

```text
SCAN → UNDERSTAND → FIX → VERIFY → MONITOR
```

---

## Why DevPilot Security?

Security tools often produce noisy, overwhelming alerts, slow down CI builds, or require uploading your proprietary code and credentials to third-party cloud servers.

DevPilot Security is built with different principles:
- **100% Local-First & Privacy Conscious**: Secret detection and AST-based code analysis run entirely on your local machine. Your code, tokens, and files are **never** uploaded to remote servers.
- **Accurate & Noise-Reduced**: Employs Shannon entropy analysis, keyword pre-filtering, and false-positive reduction filters for secrets; leverages the TypeScript Compiler API with lexical scope tracking to eliminate shadowed variable false alarms.
- **Unified Security Experience**: Scans dependencies, source-code secrets, and application logic in a single fast command (`devpilot scan`) with real progress indicators and consolidated findings.
- **Actionable Remediation**: Every finding includes specific, practical remediation guidance and safe code alternatives, not just vague CVE descriptions.
- **Automated CI/CD Ready**: Supports strict, predictable exit codes (`0`, `1`, `2`, `3`) and clean, unstyled machine-readable JSON output for effortless pipeline integration.

---

## Key Features

- **Dependency Vulnerability Scanning**: Audits installed npm packages using `package-lock.json` and the Open Source Vulnerabilities (OSV.dev) database. Features semver range validation, CVSS v3.1 vector calculations, and non-breaking upgrade suggestions.
- **Local Secret & Credential Detection**: Detects 10 categories of hardcoded credentials (AWS keys, GitHub tokens, GCP API keys, Slack webhooks, database connection strings, private key blocks, and high-entropy passwords). Includes strict in-memory masking and PEM block redaction.
- **Static Application Security Testing (SAST)**: Analyzes JavaScript, TypeScript, JSX, TSX, MJS, and CJS source code using the TypeScript Compiler API. Detects command injection, SQL injection, DOM XSS, code evaluation, unsafe React HTML, unencrypted network requests, and weak cryptography.
- **Branded Developer Terminal Experience**: Provides an interactive, non-flickering terminal UI with animated spinners on supported TTYs, clean discrete logs in CI/non-TTY environments, and automatic ASCII fallbacks on legacy consoles.
- **Zero Configuration**: Automatically detects languages, frameworks (Express, React, Next.js, NestJS, etc.), and package managers without requiring YAML or JSON configuration files.

---

## Installation

### Global Installation (Recommended for CLI use)

Install DevPilot Security globally using npm:

```bash
npm install -g devpilot-security
```

### Local Project Installation

Alternatively, add DevPilot Security as a development dependency:

```bash
npm install --save-dev devpilot-security
```

Then run commands with `npx devpilot`.

---

## Quick Start

Once installed, verify the installation and explore the available commands:

```bash
# Verify installation and view help
devpilot --help

# Check environment health
devpilot doctor

# View project mission and founder information
devpilot about

# Run a unified security scan on the current project
devpilot scan

# Or run individual specialized scanners:
devpilot security deps
devpilot security secrets
devpilot security sast
```

---

## Command Reference

DevPilot Security provides an organized, predictable CLI interface:

```text
Usage: devpilot [options] [command]

DevPilot Security — Developer security toolkit for modern applications

Options:
  -v, --version                Displays the current CLI version
  -h, --help                   Display help for command
  --no-color                   Disable colored terminal output
  --no-animation               Disable animated spinners and dynamic terminal rendering

MAIN COMMANDS
  scan [path]                  Run unified security scan (dependencies + secrets + SAST)

SECURITY COMMANDS
  security deps [path]         Scan project dependencies for known vulnerabilities via OSV
  security secrets [path]      Scan project files for hardcoded secrets, API keys, and credentials
  security sast [path]         Scan source code for static application security vulnerabilities

UTILITY COMMANDS
  about                        Show information about DevPilot Security and its founder
  doctor                       Checks the local DevPilot environment and dependencies
  help [command]               Display help for command
```

### Supported Flags & Options

- **`--json`**: Emits clean, unstyled, valid JSON stdout. Supported on `scan`, `security deps`, `security secrets`, and `security sast`.
- **`--no-color`**: Disables all ANSI colors and styling while preserving ASCII terminal symbols. Can be placed globally or on subcommands.
- **`--no-animation`**: Disables animated spinners and cursor manipulation for terminal-friendly continuous logging while keeping colors enabled.
- **Environment Variables**: DevPilot Security honors the standard `NO_COLOR=1` and `NO_ANIMATION=1` environment variables.

---

## Example Scan Reports

### Human-Readable Terminal Output

```text
┌───┐  DevPilot Security v0.1.0
│ ◆ │  Developer security toolkit for modern applications
└───┘  Target: /path/to/my-app

  ✔ Dependency Scanner [CLEAN] — 0 issues detected
  ✔ Secret Scanner [CLEAN] — 0 issues detected
  ✖ SAST Scanner [VULNERABLE] — 1 issue(s) found

 DevPilot Security Report
──────────────────────────────────────────────────────────────────────
Project:              my-app
Project Root:         /path/to/my-app
Language / Tech:      TypeScript (Express)
Package Manager:      npm
Scan Duration:        48ms
──────────────────────────────────────────────────────────────────────
Scanner Status:
  Dependency Scanner: Completed
  Secret Scanner:     Completed
  SAST Scanner:       Completed
──────────────────────────────────────────────────────────────────────
Total findings:        1
──────────────────────────────────────────────────────────────────────
Findings by Severity:
   CRITICAL  1       HIGH    0     MODERATE  0       LOW     0     UNKNOWN   0
──────────────────────────────────────────────────────────────────────
Findings Details:

1.  CRITICAL   SAST  src/db/users.ts:14:12
   Issue:        SEC-SAST-SQL-INJECTION — SQL Injection in Database Query
   Evidence:     client.query('SELECT * FROM users WHERE id = ' + userId)
   Remediation:  Use parameterized queries or prepared statements (e.g. client.query("SELECT * FROM users WHERE id = $1", [id])).

──────────────────────────────────────────────────────────────────────
ℹ Remediation Guidance: Prioritize CRITICAL and HIGH severities. Revoke any exposed secrets immediately, upgrade vulnerable dependencies, and remediate risky source-code patterns before deploying.
──────────────────────────────────────────────────────────────────────
```

### Machine-Readable JSON Output (`--json`)

In `--json` mode, banners, divider lines, and progress messages are suppressed. The stdout is guaranteed to parse with `JSON.parse()`:

```bash
devpilot scan --json > report.json
```

```json
{
  "summary": {
    "projectName": "my-app",
    "projectRoot": "/path/to/my-app",
    "framework": "Express",
    "language": "TypeScript",
    "packageManager": "npm",
    "totalFindings": 1,
    "severityCounts": {
      "CRITICAL": 1,
      "HIGH": 0,
      "MODERATE": 0,
      "LOW": 0,
      "UNKNOWN": 0
    },
    "scanStatus": "VULNERABLE",
    "durationMs": 48,
    "scanners": {
      "dependency": { "name": "Dependency Scanner", "status": "COMPLETED", "findingsCount": 0, "durationMs": 12 },
      "secret": { "name": "Secret Scanner", "status": "COMPLETED", "findingsCount": 0, "durationMs": 14 },
      "sast": { "name": "SAST Scanner", "status": "COMPLETED", "findingsCount": 1, "durationMs": 22 }
    }
  },
  "findings": [
    {
      "id": "SEC-SAST-SQL-INJECTION-src/db/users.ts:14:12",
      "scanner": "sast-scanner",
      "vulnerabilityId": "SEC-SAST-SQL-INJECTION",
      "title": "SQL Injection in Database Query",
      "severity": "CRITICAL",
      "location": {
        "filePath": "src/db/users.ts",
        "line": 14,
        "column": 12
      },
      "evidence": "client.query('SELECT * FROM users WHERE id = ' + userId)",
      "remediation": "Use parameterized queries or prepared statements (e.g. client.query(\"SELECT * FROM users WHERE id = $1\", [id]))."
    }
  ]
}
```

---

## Detailed Scanner Explanations

### 1. Dependency Scanner (`devpilot security deps`)

- **Lockfile & Package Analysis**: Parses `package-lock.json` (supporting versions 2 and 3), resolves direct vs. transitive dependencies, and properly handles npm aliases (e.g., `"my-react": "npm:react@^18.2.0"`).
- **OSV.dev Vulnerability Lookup**: Chunks unique package/version pairs into batches and queries the official Open Source Vulnerabilities (OSV) API over HTTPS. Automatically hydrates full vulnerability records with bounded concurrency and session caching.
- **Semver Range Validation**: Compares installed package versions against precise advisory version intervals (`introduced`, `fixed`, `last_affected`, and `limit`) using the `semver` engine, preventing false positive alerts for patched versions.
- **Network Requirements & Offline Handling**: Requires outbound HTTPS access to `https://api.osv.dev`. If network connectivity is unavailable, the dependency scan fails safely with exit code `2` (FAILED) and will never falsely report a clean state.
- **Limitations**: Audits installed packages recorded in `package-lock.json`. It does not execute npm scripts, resolve arbitrary lockfile-less manifests, or scan non-npm ecosystems.

### 2. Secret Scanner (`devpilot security secrets`)

- **Supported Secret Patterns**: Built-in declarative rules with false-positive reduction filters for:
  - AWS Access Key IDs (`AKIA...`) and AWS Secret Access Keys
  - Google Cloud / Firebase API keys (`AIza...`)
  - GitHub Personal Access Tokens (classic `ghp_` and fine-grained `github_pat_`), OAuth tokens, and App keys
  - GitLab Personal Access Tokens (`glpat-`), Deploy tokens, and Runner registration tokens
  - Slack Bot/User tokens (`xoxb-`, `xoxp-`) and Incoming Webhooks
  - Database connection strings containing embedded credentials (PostgreSQL, MySQL, MongoDB, Redis)
  - RSA, EC, OPENSSH, and PGP Private Key blocks
  - Generic high-entropy passwords and API key assignments
- **Masking & Multiline Redaction**: Raw secret values are **never** preserved in memory structures, console output, logs, or JSON reports. Findings display masked tokens (e.g., `AKIA...[REDACTED]...PLE`), and multiline PEM private keys are redacted line-by-line (`[REDACTED PRIVATE KEY LINE]`) to maintain accurate line numbering.
- **File Crawling & Scope**: Respects `.gitignore` rules, automatically skips build directories (`node_modules`, `dist`, `build`, `coverage`, `.git`), ignores binary files via null-byte inspection (`\0`), and enforces a strict 2 MB maximum file size limit.
- **Limitations**: Designed to detect common credential formats, token structures, and high-entropy strings. Cannot detect obfuscated, encrypted, or split keys.

### 3. Static Application Security Testing (SAST) (`devpilot security sast`)

DevPilot Security parses source files into an Abstract Syntax Tree (AST) using the TypeScript Compiler API without executing scanned project code. It implements safe import resolution and lexical scope tracking.

#### The 7 Implemented SAST Rules:

1. **`SEC-SAST-SQL-INJECTION`** (CWE-89, OWASP A03:2021)
   - *Rule ID*: `SEC-SAST-SQL-INJECTION`
   - *Name*: SQL Injection in Database Query
   - *Severity / Confidence*: `CRITICAL` / `HIGH`
   - *Detection*: Dynamically constructed SQL queries (string concatenation, dynamic template literals, or Prisma `$queryRawUnsafe`) passed to database query methods (`client.query()`, `pool.query()`, `sqlite.all()`, etc.).
   - *Safe patterns*: Parameterized queries with placeholder arrays, static queries, and tagged template literals (`prisma.$queryRaw` or `sql\``).
2. **`SEC-SAST-COMMAND-INJECTION`** (CWE-78, OWASP A03:2021)
   - *Rule ID*: `SEC-SAST-COMMAND-INJECTION`
   - *Name*: Command Injection via child_process.exec()
   - *Severity / Confidence*: `CRITICAL` / `MEDIUM` (dynamic commands); `LOW` / `HIGH` (compile-time static commands)
   - *Detection*: Dynamic commands or unvalidated variables passed to `child_process.exec()` or `execSync()`.
   - *Safe patterns*: Using `execFile()` or `spawn()` with an executable binary and a separate array of string arguments, avoiding `shell: true`.
3. **`SEC-SAST-INNERHTML`** (CWE-79, OWASP A03:2021)
   - *Rule ID*: `SEC-SAST-INNERHTML`
   - *Name*: Unsafe DOM HTML Injection (innerHTML / outerHTML / insertAdjacentHTML)
   - *Category*: DOM XSS (Cross-Site Scripting)
   - *Severity / Confidence*: `HIGH` / `HIGH`
   - *Detection*: Unescaped dynamic strings assigned to DOM insertion sinks (`element.innerHTML`, `element.outerHTML`, `element.insertAdjacentHTML()`). Harmless DOM clearing assignments (`element.innerHTML = ''`) are suppressed.
   - *Safe patterns*: Pre-sanitizing HTML using verified sanitizers (e.g. `DOMPurify.sanitize()`), static markup, or using `textContent`.
4. **`SEC-SAST-EVAL`** (CWE-95, CWE-94, OWASP A03:2021)
   - *Rule ID*: `SEC-SAST-EVAL`
   - *Name*: Dynamic Code Execution via eval() or Function()
   - *Severity / Confidence*: `CRITICAL` / `HIGH` (dynamic expressions or `Function` constructor); `MODERATE` / `HIGH` (static strings)
   - *Detection*: Dynamic code evaluation via global `eval()`, `window.eval()`, `globalThis.eval()`, or the `Function` constructor.
   - *Safe patterns*: `JSON.parse()` for serialized data, Web Workers for isolated execution, or native mapping dispatch tables.
5. **`SEC-SAST-REACT-DANGEROUS-HTML`** (CWE-79, OWASP A03:2021)
   - *Rule ID*: `SEC-SAST-REACT-DANGEROUS-HTML`
   - *Name*: Unsafe HTML Injection via React dangerouslySetInnerHTML
   - *Severity / Confidence*: `HIGH` / `HIGH`
   - *Detection*: Assigning dynamic variables or expressions to React's `dangerouslySetInnerHTML={{ __html: ... }}`.
   - *Safe patterns*: Wrapping dynamic markup in `DOMPurify.sanitize()` or using standard JSX elements.
6. **`SEC-SAST-INSECURE-HTTP`** (CWE-319, OWASP A02:2021)
   - *Rule ID*: `SEC-SAST-INSECURE-HTTP`
   - *Name*: Insecure HTTP Network Request
   - *Severity / Confidence*: `MODERATE` / `HIGH`
   - *Detection*: Cleartext `http://` or `ws://` network endpoints used in `fetch()`, `axios`, `XMLHttpRequest`, or `WebSocket`.
   - *Safe patterns*: Encrypted protocols (`https://`, `wss://`). Local loopback endpoints (`localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`) and schema URLs (e.g. `http://www.w3.org/...`, `http://json-schema.org/...`) are deliberately recognized as safe development/namespace exceptions and ignored.
7. **`SEC-SAST-WEAK-CRYPTO`** (CWE-327, CWE-328, CWE-338, OWASP A02:2021)
   - *Rule ID*: `SEC-SAST-WEAK-CRYPTO`
   - *Name*: Use of Weak Cryptographic Algorithm or Insecure PRNG
   - *Severity / Confidence*: `HIGH` / `HIGH`
   - *Detection*: Broken hash algorithms (MD5, SHA-1), deprecated ciphers (`crypto.createCipher()`, DES, RC4), and cryptographically insecure pseudo-random numbers (`Math.random()`) used in security-sensitive contexts (tokens, secrets, passwords, auth keys).
   - *Safe patterns*: Modern cryptographic hashes (SHA-256, SHA-512), `crypto.createCipheriv()`, and `crypto.randomBytes()`.

#### SAST Architecture & Limitations

- **AST Pattern & Scope Analysis**: DevPilot's SAST engine inspects AST syntax nodes, tracks imports (`import * as cp`, CommonJS `require()`), and models lexical scopes.
- **Current Boundaries**: The current engine is pattern- and AST-based. It does not perform full interprocedural or cross-file dataflow taint analysis. It cannot guarantee detection of every vulnerability or certify that code is completely bug-free.

---

## Safe vs. Unsafe Code Reference

| Vulnerability Category | Unsafe Code | Safe Code |
| :--- | :--- | :--- |
| **SQL Injection** | `db.query('SELECT * FROM users WHERE id = ' + id)` | `db.query('SELECT * FROM users WHERE id = $1', [id])` |
| **Prisma Queries** | `prisma.$queryRawUnsafe('SELECT * FROM items WHERE id = ' + id)` | `prisma.$queryRaw\`SELECT * FROM items WHERE id = ${id}\`` |
| **Command Injection** | `exec('ping -c 1 ' + host)` | `execFile('ping', ['-c', '1', host])` |
| **DOM XSS** | `el.innerHTML = '<div>' + userComment + '</div>'` | `el.innerHTML = DOMPurify.sanitize(userComment)` |
| **React XSS** | `<div dangerouslySetInnerHTML={{ __html: userHtml }} />` | `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userHtml) }} />` |
| **Code Evaluation** | `eval(userPayload)` | `JSON.parse(userPayload)` |
| **Network Requests** | `fetch('http://api.myservice.com/v1/data')` | `fetch('https://api.myservice.com/v1/data')` |
| **Hashing** | `crypto.createHash('md5').update(data)` | `crypto.createHash('sha256').update(data)` |
| **Tokens / Secrets** | `const token = Math.random().toString(36)` | `const token = crypto.randomBytes(32).toString('hex')` |

---

## CLI Exit Codes

DevPilot Security returns standardized, predictable process exit codes across both unified scanning (`devpilot scan`) and all standalone security commands (`devpilot security deps`, `devpilot security secrets`, `devpilot security sast`):

| Exit Code | Status | Meaning across Unified and Standalone Scanners |
| :---: | :--- | :--- |
| **`0`** | **CLEAN** | Scan completed successfully with zero findings (no vulnerabilities, no secrets, or no SAST issues detected). |
| **`1`** | **VULNERABLE** | Scan completed successfully and detected one or more security findings (vulnerabilities, hardcoded secrets, or risky AST patterns). |
| **`2`** | **FAILED** | Scan encountered an unrecoverable failure (e.g. missing `package-lock.json`, network unavailable during dependency lookup, invalid target directory). Scans that fail are never certified clean. |
| **`3`** | **PARTIAL** | Scan completed partially with warnings (e.g. recoverable syntax/parse errors, files exceeding 2 MB size limits, or unhydrated advisories). Even with zero findings in analyzed files, partial scans are never certified clean. |

Utility commands (`devpilot about`, `devpilot doctor`, and `devpilot --help`) exit with code `0` on successful completion. Invalid CLI arguments, unknown commands, or unrecognized options exit with code `1` via Commander.

---

## Supported Platforms & Prerequisites

- **Node.js**: `>= 18.0.0` (ESM and native `fetch` required)
- **Package Manager**: npm `>= 9.0.0` (A valid `package-lock.json` v2 or v3 is required for dependency vulnerability scanning)
- **Operating Systems**: Linux, macOS, and Windows (PowerShell, CMD, Windows Terminal)
- **Source Languages**: JavaScript (ES5+), TypeScript, JSX, TSX, MJS, and CJS

---

## Authorized-Use & Safety Boundaries

DevPilot Security is designed strictly for authorized security analysis, code quality auditing, and defensive software engineering:
1. **100% Non-Destructive**: Never mutates, deletes, or alters scanned files or package manifests.
2. **Defensive Testing**: Only scan projects, repositories, and dependencies that you own or have explicit authorization to inspect.
3. **No Warranty of Total Protection**: Security tools reduce risk but cannot guarantee total immunity. DevPilot Security should be used as one component of a layered defense-in-depth strategy.

---

## Contributing

We welcome community contributions, bug reports, and rule suggestions. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, coding conventions, and pull request guidelines.

---

## Security Policy

For information on reporting security vulnerabilities in DevPilot Security itself, please review our [SECURITY.md](./SECURITY.md).

---

## License

DevPilot Security is open-source software licensed under the [MIT License](./LICENSE).

Copyright (c) 2026 Pranay Khodade

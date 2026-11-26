# DevPilot Security

**DevPilot Security** is an open-source developer security toolkit designed to help engineering teams identify, understand, and address application security risks early in the software development lifecycle.

The long-term workflow for DevPilot Security is:

```
SCAN → UNDERSTAND → FIX → VERIFY → MONITOR
```

---

## Current CLI Features

### 1. Environment & Project Inspection
- **`devpilot --help`**: Displays the product description, options, and list of available commands.
- **`devpilot --version`** (`-v`): Displays the installed DevPilot CLI version.
- **`devpilot doctor`**: Inspects the local environment and outputs DevPilot version, Node.js runtime version, operating system details, working directory, and environment operational readiness.
- **`devpilot scan [path]`**: Inspects target project metadata (root directory, `package.json` existence, detected package manager, language, and framework).

### 2. Dependency Vulnerability Scanner
- **`devpilot security deps [path]`**: Performs a read-only security audit of installed npm dependencies using `package-lock.json` (v2 and v3) and the official Open Source Vulnerabilities (OSV) database.
  - **Full Advisory Hydration**: Retrieves detailed advisory records (`GET /v1/vulns/{id}`) with in-memory caching and bounded concurrency.
  - **Accurate Semver Range Matching**: Validates installed package versions against advisory `introduced`, `fixed`, `last_affected`, `limit` intervals, and explicit version lists to eliminate false positives.
  - **CVSS Scoring & Vector Interpretation**: Evaluates CVSS v3 / v3.1 vector strings and numeric scores to accurately categorize severities into `CRITICAL`, `HIGH`, `MODERATE`, and `LOW`.
  - **Intelligent Remediation**: Recommends the safest upgrade path (patch/minor updates within the current major line vs. notifying when breaking major bumps are required).
  - **Monorepo & Workspace Filtering**: Automatically ignores local workspace links (`link: true`, `file:`, `workspace:`), ensuring internal proprietary package names are never sent to external APIs.
  - **npm Alias Support**: Accurately tracks aliased npm packages (e.g., `"my-react": "npm:react@^18.2.0"`) as direct dependencies.
  - **Advisory Deduplication**: Unifies duplicate advisories sharing aliases (CVE, GHSA, OSV) for the same installed dependency.
- **`devpilot security deps [path] --json`**: Outputs structured, machine-readable JSON findings with complete scan summaries, direct vs. transitive classification, and detailed evidence.

---

## CLI Exit Codes

DevPilot Security returns predictable, standardized process exit codes designed for local development and CI/CD pipelines:

| Exit Code | Status | Meaning |
| :---: | :--- | :--- |
| **`0`** | **CLEAN** | Scan completed successfully. No known vulnerabilities were identified in installed dependencies. |
| **`1`** | **VULNERABLE** | Scan completed successfully, but one or more vulnerabilities were discovered. |
| **`2`** | **FAILED** | Scan failed or could not complete reliably (e.g., missing `package-lock.json`, invalid JSON syntax, network unavailable). |
| **`3`** | **PARTIAL** | Scan completed partially because upstream advisory details could not be fully hydrated (e.g., upstream 404, rate limit, or timeout). Cannot be certified clean. |

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
│   │   │   ├── scan.ts                 # Project inspector command
│   │   │   └── security.ts             # Security scanning & exit code handling
│   │   └── index.ts                    # Commander CLI entry point
│   ├── core/
│   │   ├── finding.ts                  # Standardized SecurityFinding interface & severity model
│   │   └── project-detector.ts         # Framework and language detection engine
│   ├── scanners/
│   │   └── dependency/
│   │       ├── types.ts                # Lockfile & OSV client data models
│   │       ├── semver-matcher.ts       # Accurate semver range and event interval evaluator
│   │       ├── cvss-helper.ts          # FIRST.org CVSS v3.1 vector calculator & scoring
│   │       ├── lockfile-parser.ts      # package-lock.json v2/v3 parser (workspaces & aliases)
│   │       ├── osv-client.ts           # OSV batch client & advisory hydration with cache
│   │       ├── dependency-scanner.ts   # Scanner orchestrator & finding normalizer
│   │       └── index.ts                # Scanner exports
│   ├── utils/
│   │   └── version.ts                  # Safe CLI version resolution
│   └── index.ts                        # Library public API exports
├── tests/
│   ├── cli/
│   │   └── exit-codes.test.ts          # Tests for Exit Codes 0, 1, 2, and 3
│   ├── doctor.test.ts                  # Environment diagnostic tests
│   ├── project-detector.test.ts        # Project detection tests
│   └── scanners/
│       └── dependency/
│           ├── semver-matcher.test.ts  # Semver range matching & prerelease tests
│           ├── cvss-helper.test.ts     # CVSS vector calculation tests
│           ├── lockfile-parser.test.ts # Lockfile parsing, aliases & workspace tests
│           ├── osv-client.test.ts      # OSV API client, cache & hydration tests
│           └── dependency-scanner.test.ts # End-to-end scanner & deduplication tests
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

- **100% Read-Only**: The dependency scanner never modifies `package.json`, `package-lock.json`, or any project files.
- **Privacy Conscious**: Filters workspace links and file dependencies. Never transmits internal package names, source code, or environment files.
- **Zero Package Execution**: Never invokes package lifecycle scripts (`postinstall`, etc.) or arbitrary shell commands.
- **Fail-Safe Status**: Network timeouts or corrupted lockfiles trigger exit code `2` (`FAILED`) and are never reported as clean.

# Contributing to DevPilot Security

Thank you for your interest in contributing to **DevPilot Security**! We welcome bug reports, documentation updates, rule improvements, and feature contributions.

---

## Development Prerequisites

- **Node.js**: `>= 18.0.0`
- **npm**: `>= 9.0.0`
- **Git**

---

## Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pranaykhodade1922-dot/Devpilot.git
   cd Devpilot
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Verify the test suite and typechecking:**
   ```bash
   npm run typecheck
   npm test
   ```

4. **Build the production bundle:**
   ```bash
   npm run build
   ```

5. **Run the local CLI during development:**
   ```bash
   npm run dev -- --help
   npm run dev -- scan .
   ```

---

## Project Structure Overview

```text
src/
├── cli/
│   ├── commands/             # CLI command implementations (scan, security, doctor, about)
│   ├── ui/                   # DevPilot Terminal Experience (theme, formatters, progress coordinator)
│   └── index.ts              # Commander entry point
├── core/
│   ├── finding.ts            # SecurityFinding model and severity definitions
│   └── project-detector.ts   # Project language/framework detection
├── scanners/
│   ├── dependency/           # OSV client, lockfile parser, semver matcher
│   ├── secret/               # File crawler, Shannon entropy, secret regex rules, masking
│   └── sast/                 # TypeScript Compiler AST parser, scope tracker, SAST rules
└── index.ts                  # Public library exports
```

---

## Testing & Quality Expectations

All contributions are expected to maintain our high standard of code quality and security:

- **Strict Type Checking**: Must pass `npm run typecheck` (`tsc --noEmit`) with zero errors.
- **Comprehensive Unit Tests**: All new features, bug fixes, and rules must include Vitest tests under `tests/`.
- **Zero Real Secrets**: Test fixtures must **never** contain real credentials, production API keys, or live tokens. Use synthetic, mock identifiers (e.g., `AKIAIOSFODNN7EXAMPLE`).
- **No Path Leaks**: Never hardcode personal host paths. Keep relative path conventions.
- **Fail-Safe Scanner Design**: Scanners must never crash or throw unhandled exceptions. Errors should result in clear, documented exit codes (`FAILED` or `PARTIAL`).

---

## Reporting Bugs

1. Search the [GitHub Issues](https://github.com/pranaykhodade1922-dot/Devpilot/issues) to ensure the issue hasn't already been reported.
2. If opening a new issue, include:
   - Your Node.js version, OS, and DevPilot version (`devpilot doctor`).
   - Clear reproduction steps or a minimal sample project.
   - Expected vs. actual behavior.
   - Do **not** post real passwords, tokens, or sensitive proprietary source code in public issues.

---

## Pull Request Guidelines

1. Fork the repository and create a feature branch (`git checkout -b feat/my-new-rule`).
2. Implement your changes along with corresponding unit tests.
3. Run the validation checks:
   ```bash
   npm run typecheck
   npm test
   npm run build
   ```
4. Write clear, concise commit messages following standard conventions (e.g. `feat: add rule SEC-SAST-EXAMPLE`).
5. Open a Pull Request describing your changes, motivation, and test coverage.

Thank you for helping make developer security accessible and effective!

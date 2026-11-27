import { describe, it, expect } from 'vitest';
import {
  isTTY,
  isCI,
  isDumbTerminal,
  hasNoColor,
  hasNoAnimation,
  shouldAnimate,
  shouldUseColor,
  getTerminalWidth,
  stripAnsi,
  formatBanner,
  formatSeverityBadge,
  formatScannerBadge,
  formatDivider,
  formatFindingHeader,
  formatSectionHeader,
  formatScanSummarySection,
  BRAND_CONSTANTS,
  DIVIDER_LENGTHS,
  SEVERITY_BADGE_TEXT,
  SEVERITY_PLAIN_TAGS
} from '../../src/cli/ui/index.js';
import type { SecurityFinding, SeverityLevel } from '../../src/core/finding.js';

describe('DevPilot Terminal Experience (DTE) — UI Foundation', () => {
  describe('Terminal Environment Detection (terminal.ts)', () => {
    it('detects TTY stream state accurately', () => {
      expect(isTTY({ stream: { isTTY: true } })).toBe(true);
      expect(isTTY({ stream: { isTTY: false } })).toBe(false);
      expect(isTTY({ stream: {} })).toBe(false);
    });

    it('detects CI environments across multiple standard CI env vars', () => {
      expect(isCI({ env: { CI: 'true' } })).toBe(true);
      expect(isCI({ env: { GITHUB_ACTIONS: 'true' } })).toBe(true);
      expect(isCI({ env: { GITLAB_CI: 'true' } })).toBe(true);
      expect(isCI({ env: { CONTINUOUS_INTEGRATION: '1' } })).toBe(true);
      expect(isCI({ env: {} })).toBe(false);
    });

    it('detects dumb terminals via TERM=dumb', () => {
      expect(isDumbTerminal({ env: { TERM: 'dumb' } })).toBe(true);
      expect(isDumbTerminal({ env: { TERM: 'xterm-256color' } })).toBe(false);
      expect(isDumbTerminal({ env: {} })).toBe(false);
    });

    it('respects NO_COLOR, explicit --no-color, and TERM=dumb', () => {
      expect(hasNoColor({ env: { NO_COLOR: '1' } })).toBe(true);
      expect(hasNoColor({ env: { NO_COLOR: '' } })).toBe(false);
      expect(hasNoColor({ env: { TERM: 'dumb' } })).toBe(true);
      expect(hasNoColor({ argv: ['node', 'devpilot', 'scan', '--no-color'] })).toBe(true);
      expect(hasNoColor({ argv: ['node', 'devpilot', 'scan', '--color=false'] })).toBe(true);
      expect(hasNoColor({ env: {}, argv: ['node', 'devpilot', 'scan'] })).toBe(false);
    });

    it('detects animation disabling via NO_ANIMATION and --no-animation', () => {
      expect(hasNoAnimation({ env: { NO_ANIMATION: '1' } })).toBe(true);
      expect(hasNoAnimation({ env: { NO_ANIMATION: '' } })).toBe(false);
      expect(hasNoAnimation({ argv: ['node', 'devpilot', 'scan', '--no-animation'] })).toBe(true);
      expect(hasNoAnimation({ env: {}, argv: ['node', 'devpilot', 'scan'] })).toBe(false);
    });

    it('evaluates shouldAnimate() based on TTY, CI, and animation flags', () => {
      // Interactive non-CI TTY -> should animate
      expect(
        shouldAnimate({
          stream: { isTTY: true },
          env: { TERM: 'xterm-256color' },
          argv: []
        })
      ).toBe(true);

      // Non-TTY stream -> should NOT animate
      expect(
        shouldAnimate({
          stream: { isTTY: false },
          env: {},
          argv: []
        })
      ).toBe(false);

      // CI environment -> should NOT animate
      expect(
        shouldAnimate({
          stream: { isTTY: true },
          env: { CI: 'true' },
          argv: []
        })
      ).toBe(false);

      // Explicit --no-animation -> should NOT animate
      expect(
        shouldAnimate({
          stream: { isTTY: true },
          env: {},
          argv: ['--no-animation']
        })
      ).toBe(false);

      // Dumb terminal -> should NOT animate
      expect(
        shouldAnimate({
          stream: { isTTY: true },
          env: { TERM: 'dumb' },
          argv: []
        })
      ).toBe(false);
    });

    it('evaluates shouldUseColor() correctly', () => {
      expect(shouldUseColor({ env: { NO_COLOR: '1' } })).toBe(false);
      expect(shouldUseColor({ env: { TERM: 'dumb' } })).toBe(false);
      expect(shouldUseColor({ env: {} })).toBe(true);
    });

    it('retrieves terminal width safely with fallback', () => {
      expect(getTerminalWidth({ stream: { columns: 120 } })).toBe(120);
      expect(getTerminalWidth({ stream: { columns: 0 } }, 80)).toBe(80);
    });

    it('strips all ANSI color and cursor codes from formatted strings', () => {
      const colored = '\u001b[31mError:\u001b[39m \u001b[1mCritical failure\u001b[22m';
      expect(stripAnsi(colored)).toBe('Error: Critical failure');
    });
  });

  describe('Theme and Brand Constants (theme.ts)', () => {
    it('defines brand constants correctly', () => {
      expect(BRAND_CONSTANTS.name).toBe('DevPilot Security');
      expect(BRAND_CONSTANTS.repositoryUrl).toContain('Devpilot');
      expect(DIVIDER_LENGTHS.full).toBe(70);
    });

    it('defines severity badge text and plain tags for all five levels', () => {
      const levels: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];
      for (const level of levels) {
        expect(SEVERITY_BADGE_TEXT[level]).toBeDefined();
        expect(SEVERITY_PLAIN_TAGS[level]).toBeDefined();
        expect(SEVERITY_PLAIN_TAGS[level]).toBe(`[${level}]`);
      }
    });
  });

  describe('Pure Formatters (formatters.ts)', () => {
    it('formats dividers with customizable length and plain-text output', () => {
      const fullPlain = formatDivider(70, { color: false });
      expect(fullPlain).toBe('─'.repeat(70));
      expect(stripAnsi(fullPlain)).toBe(fullPlain);

      const compactPlain = formatDivider(50, { color: false });
      expect(compactPlain).toBe('─'.repeat(50));
    });

    it('formats startup banner with logo and optional target path', () => {
      const bannerPlain = formatBanner({
        color: false,
        version: '0.1.0',
        targetPath: '/workspace/app'
      });

      expect(bannerPlain).toContain('DevPilot Security v0.1.0');
      expect(bannerPlain).toContain('Target: /workspace/app');
      expect(bannerPlain).toContain('┌───┐');
      expect(bannerPlain).toContain('└───┘');
      // Must contain zero ANSI codes
      expect(stripAnsi(bannerPlain)).toBe(bannerPlain);
    });

    it('formats all five severity badges in both colored and plain text', () => {
      const levels: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];
      for (const level of levels) {
        const plainBadge = formatSeverityBadge(level, { color: false });
        expect(plainBadge).toBe(`[${level}]`);
        expect(stripAnsi(plainBadge)).toBe(plainBadge);

        const coloredBadge = formatSeverityBadge(level, { color: true });
        expect(stripAnsi(coloredBadge)).toBe(SEVERITY_BADGE_TEXT[level]);
      }
    });

    it('formats scanner badges in both colored and plain text', () => {
      expect(formatScannerBadge('secret-scanner', { color: false })).toBe('[SECRET]');
      expect(formatScannerBadge('sast-scanner', { color: false })).toBe('[SAST]');
      expect(formatScannerBadge('dependency-scanner', { color: false })).toBe('[DEPENDENCY]');

      const coloredSecret = formatScannerBadge('secret-scanner', { color: true });
      expect(stripAnsi(coloredSecret)).toBe(' SECRET ');
    });

    it('formats finding card headers with accurate coordinates and plain text compatibility', () => {
      const sampleFinding: SecurityFinding = {
        id: 'SEC-SAST-SQL-INJECTION-src/db.ts:14:12',
        scanner: 'sast-scanner',
        packageName: 'src/db.ts',
        installedVersion: 'L14:C12',
        vulnerabilityId: 'SEC-SAST-SQL-INJECTION',
        title: 'SQL Injection in Database Query',
        description: 'Dynamic query vulnerability',
        severity: 'CRITICAL',
        evidence: 'db.query("SELECT ... " + id)',
        remediation: 'Use parameterized queries',
        dependencyType: 'direct',
        location: {
          filePath: 'src/db.ts',
          line: 14,
          column: 12,
          endLine: 14,
          endColumn: 45
        },
        fixedVersions: [],
        references: []
      };

      const plainHeader = formatFindingHeader(1, sampleFinding, { color: false });
      expect(plainHeader).toBe('1. [CRITICAL] [SAST] src/db.ts:14:12');
      expect(stripAnsi(plainHeader)).toBe(plainHeader);

      const coloredHeader = formatFindingHeader(1, sampleFinding, { color: true });
      expect(stripAnsi(coloredHeader)).toContain('1.  CRITICAL   SAST  src/db.ts:14:12');
    });

    it('formats scan summary sections for CLEAN, VULNERABLE, FAILED, and PARTIAL', () => {
      // CLEAN
      const cleanPlain = formatScanSummarySection(
        {
          totalFindings: 0,
          severityCounts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
          scanStatus: 'CLEAN',
          durationMs: 40
        },
        { color: false }
      );
      expect(cleanPlain).toContain('Scan Completed: Clean (Exit Code 0)');
      expect(stripAnsi(cleanPlain)).toBe(cleanPlain);

      // VULNERABLE
      const vulnPlain = formatScanSummarySection(
        {
          totalFindings: 3,
          severityCounts: { CRITICAL: 1, HIGH: 2, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
          scanStatus: 'VULNERABLE',
          durationMs: 55
        },
        { color: false }
      );
      expect(vulnPlain).toContain('Total Findings: 3  (55ms total duration)');
      expect(vulnPlain).toContain('CRITICAL: 1  HIGH: 2  MODERATE: 0  LOW: 0  UNKNOWN: 0');
      expect(stripAnsi(vulnPlain)).toBe(vulnPlain);

      // FAILED
      const failedPlain = formatScanSummarySection(
        {
          totalFindings: 0,
          severityCounts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
          scanStatus: 'FAILED',
          durationMs: 12
        },
        { color: false }
      );
      expect(failedPlain).toContain('Scan Failed (Exit Code 2)');
      expect(stripAnsi(failedPlain)).toBe(failedPlain);

      // PARTIAL
      const partialPlain = formatScanSummarySection(
        {
          totalFindings: 0,
          severityCounts: { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 },
          scanStatus: 'PARTIAL',
          durationMs: 15
        },
        { color: false }
      );
      expect(partialPlain).toContain('Scan Partially Completed (Exit Code 3)');
      expect(stripAnsi(partialPlain)).toBe(partialPlain);
    });

    it('formats section headers with plain text fallback', () => {
      expect(formatSectionHeader('Scan Details', { color: false })).toBe('Scan Details');
    });
  });
});

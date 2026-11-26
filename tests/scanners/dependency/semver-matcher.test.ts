import { describe, it, expect } from 'vitest';
import {
  evaluateAffectedStatus,
  isVersionInEvents,
  normalizeSemver
} from '../../../src/scanners/dependency/semver-matcher.js';
import type { OsvAffected } from '../../../src/scanners/dependency/types.js';

describe('Semver Matcher', () => {
  describe('normalizeSemver', () => {
    it('normalizes valid semver strings and prefixes', () => {
      expect(normalizeSemver('1.2.3')).toBe('1.2.3');
      expect(normalizeSemver('v1.2.3')).toBe('1.2.3');
      expect(normalizeSemver('  2.0.0-beta.1  ')).toBe('2.0.0-beta.1');
    });

    it('returns null for non-semver strings', () => {
      expect(normalizeSemver('invalid-version')).toBeNull();
      expect(normalizeSemver('')).toBeNull();
    });
  });

  describe('isVersionInEvents', () => {
    it('matches versions between introduced and fixed', () => {
      const events = [{ introduced: '1.0.0' }, { fixed: '1.2.5' }];

      expect(isVersionInEvents('1.0.0', events).inRange).toBe(true);
      expect(isVersionInEvents('1.1.0', events).inRange).toBe(true);
      expect(isVersionInEvents('1.2.4', events).inRange).toBe(true);

      // 1.2.5 is fixed (exclusive)
      expect(isVersionInEvents('1.2.5', events).inRange).toBe(false);
      expect(isVersionInEvents('1.3.0', events).inRange).toBe(false);

      // Prior to introduced
      expect(isVersionInEvents('0.9.0', events).inRange).toBe(false);
    });

    it('matches introduced: 0 correctly', () => {
      const events = [{ introduced: '0' }, { fixed: '2.0.0' }];

      expect(isVersionInEvents('0.0.1', events).inRange).toBe(true);
      expect(isVersionInEvents('1.9.9', events).inRange).toBe(true);
      expect(isVersionInEvents('2.0.0', events).inRange).toBe(false);
    });

    it('supports last_affected events (inclusive upper bound)', () => {
      const events = [{ introduced: '1.0.0' }, { last_affected: '1.5.0' }];

      expect(isVersionInEvents('1.0.0', events).inRange).toBe(true);
      expect(isVersionInEvents('1.5.0', events).inRange).toBe(true);
      // Beyond last_affected
      expect(isVersionInEvents('1.5.1', events).inRange).toBe(false);
    });

    it('supports limit events', () => {
      const events = [{ introduced: '1.0.0' }, { limit: '2.0.0' }];

      expect(isVersionInEvents('1.5.0', events).inRange).toBe(true);
      expect(isVersionInEvents('2.0.0', events).inRange).toBe(false);
    });

    it('handles multiple ranges in the same event list', () => {
      // E.g. [1.0.0, 1.2.0) and [2.0.0, 2.2.0)
      const events = [
        { introduced: '1.0.0' },
        { fixed: '1.2.0' },
        { introduced: '2.0.0' },
        { fixed: '2.2.0' }
      ];

      expect(isVersionInEvents('1.1.0', events).inRange).toBe(true);
      expect(isVersionInEvents('1.2.0', events).inRange).toBe(false);
      expect(isVersionInEvents('1.5.0', events).inRange).toBe(false);
      expect(isVersionInEvents('2.1.0', events).inRange).toBe(true);
      expect(isVersionInEvents('2.2.0', events).inRange).toBe(false);
    });

    it('handles prerelease versions properly', () => {
      const events = [{ introduced: '1.0.0-alpha' }, { fixed: '1.0.0' }];

      expect(isVersionInEvents('1.0.0-beta', events).inRange).toBe(true);
      expect(isVersionInEvents('1.0.0', events).inRange).toBe(false);
    });
  });

  describe('evaluateAffectedStatus', () => {
    it('evaluates explicit versions list correctly', () => {
      const affected: OsvAffected = {
        package: { name: 'pkg', ecosystem: 'npm' },
        versions: ['1.0.1', '1.0.2', '1.0.3-beta']
      };

      const match1 = evaluateAffectedStatus('1.0.1', affected);
      expect(match1.isAffected).toBe(true);

      const matchBeta = evaluateAffectedStatus('1.0.3-beta', affected);
      expect(matchBeta.isAffected).toBe(true);

      const matchUnaffected = evaluateAffectedStatus('1.0.4', affected);
      expect(matchUnaffected.isAffected).toBe(false);
    });

    it('evaluates semver ranges and distinguishes unaffected versions', () => {
      const affected: OsvAffected = {
        package: { name: 'pkg', ecosystem: 'npm' },
        ranges: [
          {
            type: 'SEMVER',
            events: [{ introduced: '2.0.0' }, { fixed: '2.1.4' }]
          }
        ]
      };

      // In range
      const inRange = evaluateAffectedStatus('2.1.0', affected);
      expect(inRange.isAffected).toBe(true);

      // Before range
      const beforeRange = evaluateAffectedStatus('1.9.9', affected);
      expect(beforeRange.isAffected).toBe(false);

      // Patched version must not be reported as vulnerable
      const patched = evaluateAffectedStatus('2.1.4', affected);
      expect(patched.isAffected).toBe(false);
      expect(patched.isIndeterminate).toBe(false);
    });

    it('reports indeterminate when advisory contains malformed or empty ranges', () => {
      const affectedMalformed: OsvAffected = {
        package: { name: 'pkg', ecosystem: 'npm' },
        ranges: [
          {
            type: 'ECOSYSTEM',
            events: []
          }
        ]
      };

      const result = evaluateAffectedStatus('1.0.0', affectedMalformed);
      expect(result.isAffected).toBe(false);
      expect(result.isIndeterminate).toBe(true);
    });

    it('reports indeterminate when installed version is not valid semver', () => {
      const affected: OsvAffected = {
        package: { name: 'pkg', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] }]
      };

      const result = evaluateAffectedStatus('invalid-sha-git', affected);
      expect(result.isAffected).toBe(false);
      expect(result.isIndeterminate).toBe(true);
      expect(result.reason).toContain('is not valid semver');
    });

    it('returns indeterminate when no ranges or versions exist', () => {
      const affected: OsvAffected = {
        package: { name: 'pkg', ecosystem: 'npm' }
      };

      const result = evaluateAffectedStatus('1.0.0', affected);
      expect(result.isAffected).toBe(false);
      expect(result.isIndeterminate).toBe(true);
    });
  });
});

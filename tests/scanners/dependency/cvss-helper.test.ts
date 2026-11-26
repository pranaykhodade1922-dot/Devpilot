import { describe, it, expect } from 'vitest';
import {
  calculateCvss3BaseScore,
  evaluateCvss,
  scoreToSeverity
} from '../../../src/scanners/dependency/cvss-helper.js';

describe('CVSS Helper', () => {
  describe('calculateCvss3BaseScore against FIRST.org reference vectors', () => {
    it('calculates CVSS 3.1 base score for standard 10.0 critical vector (Scope Changed)', () => {
      // Log4Shell-like CVSS 10.0: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
      const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
      const score = calculateCvss3BaseScore(vector);
      expect(score).toBe(10);
    });

    it('calculates CVSS 3.1 base score for standard 9.8 critical vector (Scope Unchanged)', () => {
      // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
      const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
      const score = calculateCvss3BaseScore(vector);
      expect(score).toBe(9.8);
    });

    it('calculates CVSS 3.1 base score for 7.5 high reference vector', () => {
      // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
      const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H';
      const score = calculateCvss3BaseScore(vector);
      expect(score).toBe(7.5);
    });

    it('calculates CVSS 3.1 base score for 5.9 moderate reference vector', () => {
      // Vitest / @vitest/mocker CVE-2026-84373 vector
      const vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N';
      const score = calculateCvss3BaseScore(vector);
      expect(score).toBe(5.9);
    });

    it('calculates CVSS 3.1 base score for 2.5 low reference vector', () => {
      // esbuild GHSA-g7r4-m6w7-qqqr vector
      const vector = 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N';
      const score = calculateCvss3BaseScore(vector);
      expect(score).toBe(2.5);
    });

    it('returns null for incomplete or invalid vector', () => {
      expect(calculateCvss3BaseScore('CVSS:3.1/INVALID')).toBeNull();
      expect(calculateCvss3BaseScore('NOT_A_VECTOR')).toBeNull();
    });
  });

  describe('scoreToSeverity', () => {
    it('maps scores to correct severity bands', () => {
      expect(scoreToSeverity(9.8)).toBe('CRITICAL');
      expect(scoreToSeverity(9.0)).toBe('CRITICAL');
      expect(scoreToSeverity(8.9)).toBe('HIGH');
      expect(scoreToSeverity(7.0)).toBe('HIGH');
      expect(scoreToSeverity(6.9)).toBe('MODERATE');
      expect(scoreToSeverity(4.0)).toBe('MODERATE');
      expect(scoreToSeverity(3.9)).toBe('LOW');
      expect(scoreToSeverity(0.5)).toBe('LOW');
      expect(scoreToSeverity(0.0)).toBe('LOW');
    });
  });

  describe('evaluateCvss', () => {
    it('evaluates direct numeric score strings and preserves score', () => {
      const res = evaluateCvss('7.5');
      expect(res.severity).toBe('HIGH');
      expect(res.score).toBe(7.5);
      expect(res.vector).toBe('7.5');
    });

    it('evaluates CVSS 3.1 vector string correctly and preserves original vector', () => {
      const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
      const res = evaluateCvss(vector);
      expect(res.severity).toBe('CRITICAL');
      expect(res.score).toBe(9.8);
      expect(res.vector).toBe(vector);
      expect(res.version).toBe('3.1');
    });

    it('confirms CVSS 4.0 is not incorrectly calculated using v3 formula', () => {
      const v4Vector = 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H';
      const res = evaluateCvss(v4Vector);
      expect(res.severity).toBe('UNKNOWN');
      expect(res.score).toBeUndefined(); // Does not invent or miscalculate
      expect(res.vector).toBe(v4Vector);
      expect(res.version).toBe('4.0');
    });
  });
});

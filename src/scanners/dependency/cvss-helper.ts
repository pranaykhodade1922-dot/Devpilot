import type { SeverityLevel, SeveritySource } from '../../core/finding.js';

export interface CvssEvaluationResult {
  severity: SeverityLevel;
  score?: number;
  vector?: string;
  version?: '3.0' | '3.1' | '4.0' | 'other';
  severitySource: SeveritySource;
}

const CVSS3_METRICS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0.0 },
  I: { H: 0.56, L: 0.22, N: 0.0 },
  A: { H: 0.56, L: 0.22, N: 0.0 }
};

function cvssRoundUp(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Calculates CVSS v3 / v3.1 base score from a vector string according to FIRST.org specification.
 */
export function calculateCvss3BaseScore(vector: string): number | null {
  const parts = vector.split('/');
  const metrics: Record<string, string> = {};

  for (const part of parts) {
    const [key, val] = part.split(':');
    if (key && val) {
      metrics[key.toUpperCase()] = val.toUpperCase();
    }
  }

  const av = CVSS3_METRICS.AV[metrics['AV'] as keyof typeof CVSS3_METRICS.AV];
  const ac = CVSS3_METRICS.AC[metrics['AC'] as keyof typeof CVSS3_METRICS.AC];
  const scope = metrics['S'];
  const ui = CVSS3_METRICS.UI[metrics['UI'] as keyof typeof CVSS3_METRICS.UI];
  const c = CVSS3_METRICS.C[metrics['C'] as keyof typeof CVSS3_METRICS.C];
  const i = CVSS3_METRICS.I[metrics['I'] as keyof typeof CVSS3_METRICS.I];
  const a = CVSS3_METRICS.A[metrics['A'] as keyof typeof CVSS3_METRICS.A];

  if (
    av === undefined ||
    ac === undefined ||
    !scope ||
    ui === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined
  ) {
    return null;
  }

  const isScopeChanged = scope === 'C';
  const prMap = isScopeChanged ? CVSS3_METRICS.PR_C : CVSS3_METRICS.PR_U;
  const pr = prMap[metrics['PR'] as keyof typeof prMap];
  if (pr === undefined) {
    return null;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact: number;
  if (isScopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) {
    return 0;
  }

  if (isScopeChanged) {
    return cvssRoundUp(Math.min(1.08 * (impact + exploitability), 10));
  }
  return cvssRoundUp(Math.min(impact + exploitability, 10));
}

export function scoreToSeverity(score: number): SeverityLevel {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MODERATE';
  if (score > 0) return 'LOW';
  return 'LOW';
}

/**
 * Parses CVSS vector or numeric score into a standardized evaluation.
 * Never calculates CVSS v4 vectors using the v3 formula.
 */
export function evaluateCvss(rawScoreOrVector: string): CvssEvaluationResult {
  const trimmed = rawScoreOrVector.trim();

  // 1. Direct numeric score e.g. "7.5"
  const numericScore = parseFloat(trimmed);
  if (!isNaN(numericScore) && numericScore >= 0 && numericScore <= 10 && !trimmed.includes(':')) {
    return {
      severity: scoreToSeverity(numericScore),
      score: numericScore,
      vector: trimmed,
      severitySource: 'explicit_score'
    };
  }

  // 2. CVSS v3.0 / v3.1 Vector string
  if (trimmed.startsWith('CVSS:3.') || trimmed.startsWith('CVSS:3.0') || trimmed.startsWith('CVSS:3.1')) {
    const score = calculateCvss3BaseScore(trimmed);
    const version = trimmed.startsWith('CVSS:3.1') ? '3.1' : '3.0';
    if (score !== null) {
      return {
        severity: scoreToSeverity(score),
        score,
        vector: trimmed,
        version,
        severitySource: 'calculated_cvss3'
      };
    }
    return {
      severity: 'UNKNOWN',
      vector: trimmed,
      version,
      severitySource: 'unknown'
    };
  }

  // 3. CVSS v4.0 Vector string (never use v3 formula)
  if (trimmed.startsWith('CVSS:4.0')) {
    return {
      severity: 'UNKNOWN',
      vector: trimmed,
      version: '4.0',
      severitySource: 'unknown'
    };
  }

  return {
    severity: 'UNKNOWN',
    vector: trimmed,
    version: 'other',
    severitySource: 'unknown'
  };
}

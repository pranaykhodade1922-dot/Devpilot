import semver from 'semver';
import type { OsvAffected, OsvAffectedEvent } from './types.js';

export interface SemverMatchResult {
  isAffected: boolean;
  isIndeterminate: boolean;
  reason: string;
}

/**
 * Normalizes a version string into a valid semver if possible.
 */
export function normalizeSemver(rawVersion: string): string | null {
  const cleaned = semver.clean(rawVersion.trim(), { loose: true });
  if (cleaned) {
    return cleaned;
  }
  const coerced = semver.coerce(rawVersion.trim(), { loose: true });
  return coerced ? coerced.version : null;
}

/**
 * Checks if a version falls within any interval defined by OSV events.
 *
 * An event list forms intervals [introduced, fixed/last_affected/limit).
 * A version is in range if it falls within ANY of the intervals.
 */
export function isVersionInEvents(
  targetVersion: string,
  events: OsvAffectedEvent[]
): { inRange: boolean; matched: boolean } {
  const normTarget = normalizeSemver(targetVersion);
  if (!normTarget) {
    return { inRange: false, matched: false };
  }

  let hasEvaluatedAnyEvent = false;

  let currentIntro: string | null = null;
  let currentFixed: string | null = null;
  let currentLastAffected: string | null = null;
  let currentLimit: string | null = null;

  const intervals: Array<{
    intro: string;
    fixed?: string;
    lastAffected?: string;
    limit?: string;
  }> = [];

  for (const event of events) {
    if (typeof event.introduced === 'string') {
      if (currentIntro !== null) {
        intervals.push({
          intro: currentIntro,
          fixed: currentFixed ?? undefined,
          lastAffected: currentLastAffected ?? undefined,
          limit: currentLimit ?? undefined
        });
        currentFixed = null;
        currentLastAffected = null;
        currentLimit = null;
      }
      currentIntro = event.introduced.trim();
      hasEvaluatedAnyEvent = true;
    } else if (typeof event.fixed === 'string') {
      currentFixed = event.fixed.trim();
      hasEvaluatedAnyEvent = true;
    } else if (typeof event.last_affected === 'string') {
      currentLastAffected = event.last_affected.trim();
      hasEvaluatedAnyEvent = true;
    } else if (typeof event.limit === 'string') {
      currentLimit = event.limit.trim();
      hasEvaluatedAnyEvent = true;
    }
  }

  if (currentIntro !== null) {
    intervals.push({
      intro: currentIntro,
      fixed: currentFixed ?? undefined,
      lastAffected: currentLastAffected ?? undefined,
      limit: currentLimit ?? undefined
    });
  }

  // Check if target falls within ANY interval
  for (const interval of intervals) {
    const isAboveIntro =
      interval.intro === '0' ||
      interval.intro === '' ||
      (() => {
        const normIntro = normalizeSemver(interval.intro);
        return normIntro ? semver.compare(normTarget, normIntro) >= 0 : false;
      })();

    if (!isAboveIntro) {
      continue;
    }

    // Check fixed (exclusive upper bound)
    if (interval.fixed) {
      const normFixed = normalizeSemver(interval.fixed);
      if (normFixed && semver.compare(normTarget, normFixed) >= 0) {
        continue;
      }
    }

    // Check last_affected (inclusive upper bound)
    if (interval.lastAffected) {
      const normLA = normalizeSemver(interval.lastAffected);
      if (normLA && semver.compare(normTarget, normLA) > 0) {
        continue;
      }
    }

    // Check limit (exclusive upper bound)
    if (interval.limit) {
      const normLimit = normalizeSemver(interval.limit);
      if (interval.limit === '*' || (normLimit && semver.compare(normTarget, normLimit) >= 0)) {
        continue;
      }
    }

    // Inside this interval!
    return { inRange: true, matched: true };
  }

  return { inRange: false, matched: hasEvaluatedAnyEvent };
}

/**
 * Validates an installed package version against an OSV affected entry.
 *
 * Checks:
 * 1. Explicit versions list (`affected.versions`)
 * 2. Semver ranges (`affected.ranges`)
 */
export function evaluateAffectedStatus(
  installedVersion: string,
  affectedEntry: OsvAffected
): SemverMatchResult {
  const normInstalled = normalizeSemver(installedVersion);
  if (!normInstalled) {
    return {
      isAffected: false,
      isIndeterminate: true,
      reason: `Installed version "${installedVersion}" is not valid semver.`
    };
  }

  // 1. Check explicit versions array if present
  if (Array.isArray(affectedEntry.versions) && affectedEntry.versions.length > 0) {
    for (const v of affectedEntry.versions) {
      if (v === installedVersion) {
        return {
          isAffected: true,
          isIndeterminate: false,
          reason: `Version ${installedVersion} explicitly listed in advisory affected versions.`
        };
      }
      const normV = normalizeSemver(v);
      if (normV && semver.eq(normInstalled, normV)) {
        return {
          isAffected: true,
          isIndeterminate: false,
          reason: `Version ${installedVersion} matches affected version ${v}.`
        };
      }
    }
  }

  // 2. Check ranges
  if (Array.isArray(affectedEntry.ranges) && affectedEntry.ranges.length > 0) {
    let hasEvaluatedRange = false;

    for (const range of affectedEntry.ranges) {
      if (!Array.isArray(range.events) || range.events.length === 0) {
        continue;
      }

      const { inRange, matched } = isVersionInEvents(installedVersion, range.events);
      if (matched) {
        hasEvaluatedRange = true;
        if (inRange) {
          return {
            isAffected: true,
            isIndeterminate: false,
            reason: `Version ${installedVersion} falls within affected range.`
          };
        }
      }
    }

    if (hasEvaluatedRange) {
      return {
        isAffected: false,
        isIndeterminate: false,
        reason: `Version ${installedVersion} is outside all specified advisory ranges.`
      };
    }
  }

  // If neither explicit versions nor valid ranges could be evaluated
  return {
    isAffected: false,
    isIndeterminate: true,
    reason: 'Advisory does not contain actionable version ranges or explicit version lists.'
  };
}

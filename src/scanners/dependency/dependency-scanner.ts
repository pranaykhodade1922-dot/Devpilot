import path from 'node:path';
import semver from 'semver';
import type {
  RemediationDetails,
  SecurityFinding,
  SeverityLevel
} from '../../core/finding.js';
import { SEVERITY_ORDER } from '../../core/finding.js';
import { evaluateCvss } from './cvss-helper.js';
import { parsePackageLock } from './lockfile-parser.js';
import { OsvClient } from './osv-client.js';
import { evaluateAffectedStatus, normalizeSemver } from './semver-matcher.js';
import type {
  DependencyProgressEvent,
  DependencyScanOptions,
  DependencyScanResult,
  DependencyScanSummary,
  InstalledDependency,
  OsvVulnerability
} from './types.js';

export interface NormalizedSeverityResult {
  severity: SeverityLevel;
  severitySource: import('../../core/finding.js').SeveritySource;
  cvssVersion?: '3.0' | '3.1' | '4.0' | 'other';
  cvssScore?: string;
  cvssVector?: string;
}

/**
 * Normalizes severity from OSV advisory data (database_specific, CVSS v3/v3.1 vector or score).
 * Never invents severity ratings; returns UNKNOWN if indeterminate.
 */
export function normalizeSeverity(
  vuln: OsvVulnerability,
  packageName?: string
): NormalizedSeverityResult {
  let bestSeverity: SeverityLevel = 'UNKNOWN';
  let severitySource: import('../../core/finding.js').SeveritySource = 'unknown';
  let cvssVersion: '3.0' | '3.1' | '4.0' | 'other' | undefined;
  let foundScore: string | undefined;
  let foundVector: string | undefined;

  // 1. Check top-level database_specific.severity
  const dbSev = vuln.database_specific?.severity;
  if (typeof dbSev === 'string') {
    const s = dbSev.trim().toUpperCase();
    if (s === 'CRITICAL') {
      bestSeverity = 'CRITICAL';
      severitySource = 'database_specific';
    } else if (s === 'HIGH') {
      bestSeverity = 'HIGH';
      severitySource = 'database_specific';
    } else if (s === 'MODERATE' || s === 'MEDIUM') {
      bestSeverity = 'MODERATE';
      severitySource = 'database_specific';
    } else if (s === 'LOW') {
      bestSeverity = 'LOW';
      severitySource = 'database_specific';
    }
  }

  // 2. Check affected database_specific.severity for this package
  if (vuln.affected && packageName) {
    const matching = vuln.affected.find(
      (a) => a.package?.name?.toLowerCase() === packageName.toLowerCase()
    );
    const affectedSev = matching?.database_specific?.severity;
    if (typeof affectedSev === 'string') {
      const s = affectedSev.trim().toUpperCase();
      if (s === 'CRITICAL') {
        bestSeverity = 'CRITICAL';
        severitySource = 'database_specific';
      } else if (s === 'HIGH' && SEVERITY_ORDER[bestSeverity] < SEVERITY_ORDER.HIGH) {
        bestSeverity = 'HIGH';
        severitySource = 'database_specific';
      } else if (
        (s === 'MODERATE' || s === 'MEDIUM') &&
        SEVERITY_ORDER[bestSeverity] < SEVERITY_ORDER.MODERATE
      ) {
        bestSeverity = 'MODERATE';
        severitySource = 'database_specific';
      } else if (s === 'LOW' && bestSeverity === 'UNKNOWN') {
        bestSeverity = 'LOW';
        severitySource = 'database_specific';
      }
    }
  }

  // 3. Check CVSS scores & vectors in severity array
  if (Array.isArray(vuln.severity)) {
    for (const sevItem of vuln.severity) {
      if (sevItem && typeof sevItem.score === 'string') {
        const evalResult = evaluateCvss(sevItem.score);
        if (evalResult.score !== undefined) {
          foundScore = String(evalResult.score);
        }
        if (evalResult.vector) {
          foundVector = evalResult.vector;
        }
        if (evalResult.version) {
          cvssVersion = evalResult.version;
        }
        if (
          evalResult.severity !== 'UNKNOWN' &&
          (bestSeverity === 'UNKNOWN' ||
            SEVERITY_ORDER[evalResult.severity] > SEVERITY_ORDER[bestSeverity])
        ) {
          bestSeverity = evalResult.severity;
          severitySource = evalResult.severitySource;
        }
      }
    }
  }

  return {
    severity: bestSeverity,
    severitySource,
    cvssVersion,
    cvssScore: foundScore,
    cvssVector: foundVector
  };
}

/**
 * Extracts all valid fixed versions for the target package from an OSV advisory.
 */
export function extractFixedVersions(
  vuln: OsvVulnerability,
  packageName: string
): string[] {
  const fixedVersions = new Set<string>();

  if (!Array.isArray(vuln.affected)) {
    return [];
  }

  for (const aff of vuln.affected) {
    if (
      aff.package?.name &&
      aff.package.name.toLowerCase() === packageName.toLowerCase()
    ) {
      if (Array.isArray(aff.ranges)) {
        for (const range of aff.ranges) {
          if (Array.isArray(range.events)) {
            for (const event of range.events) {
              if (
                event &&
                typeof event.fixed === 'string' &&
                event.fixed.trim().length > 0
              ) {
                fixedVersions.add(event.fixed.trim());
              }
            }
          }
        }
      }
    }
  }

  // Sort fixed versions in ascending semver order where possible
  return Array.from(fixedVersions).sort((a, b) => {
    const semA = normalizeSemver(a);
    const semB = normalizeSemver(b);
    if (semA && semB) {
      return semver.compare(semA, semB);
    }
    return a.localeCompare(b);
  });
}

/**
 * Computes intelligent remediation guidance for a given installed version and list of fixes.
 */
export function computeRemediation(
  packageName: string,
  installedVersion: string,
  fixedVersions: string[]
): { recommendation: string; details: RemediationDetails } {
  if (fixedVersions.length === 0) {
    return {
      recommendation: `No fixed version currently available. Review advisory references and consider replacing or mitigating usage of ${packageName}.`,
      details: {
        notes: 'No patched version released.'
      }
    };
  }

  const normInstalled = normalizeSemver(installedVersion);
  if (!normInstalled) {
    return {
      recommendation: `Upgrade ${packageName} to version ${fixedVersions.join(' or ')}.`,
      details: {
        recommendedVersion: fixedVersions[0]
      }
    };
  }

  const installedMajor = semver.major(normInstalled);

  // Check if there is a fix in the same major version that is newer than installed
  const sameMajorFixes = fixedVersions.filter((f) => {
    const normF = normalizeSemver(f);
    return normF && semver.major(normF) === installedMajor && semver.gt(normF, normInstalled);
  });

  if (sameMajorFixes.length > 0) {
    const bestFix = sameMajorFixes[0]!;
    return {
      recommendation: `Upgrade ${packageName} to version ${bestFix} (patch/minor update within current major v${installedMajor}).`,
      details: {
        recommendedVersion: bestFix,
        safeInCurrentMajor: true,
        requiresMajorUpgrade: false,
        notes: `Safe update within major version v${installedMajor}.`
      }
    };
  }

  // If no fix in current major, find the nearest higher major fix
  const higherMajorFixes = fixedVersions.filter((f) => {
    const normF = normalizeSemver(f);
    return normF && semver.gt(normF, normInstalled);
  });

  if (higherMajorFixes.length > 0) {
    const nextFix = higherMajorFixes[0]!;
    const nextMajor = normalizeSemver(nextFix) ? semver.major(normalizeSemver(nextFix)!) : undefined;
    return {
      recommendation: `Upgrade ${packageName} to version ${nextFix}. (Requires major version upgrade from v${installedMajor} to v${nextMajor ?? 'next'}; manual compatibility review recommended).`,
      details: {
        recommendedVersion: nextFix,
        safeInCurrentMajor: false,
        requiresMajorUpgrade: true,
        notes: 'Requires major version bump.'
      }
    };
  }

  // Fallback to listing all fixed versions
  return {
    recommendation: `Upgrade ${packageName} to version ${fixedVersions.join(' or ')}.`,
    details: {
      recommendedVersion: fixedVersions[fixedVersions.length - 1]
    }
  };
}

export interface CreateFindingOptions {
  isIndeterminate?: boolean;
  indeterminateReason?: string;
}

/**
 * Creates a normalized SecurityFinding for an installed package and full advisory record.
 */
export function createSecurityFinding(
  dep: InstalledDependency,
  vuln: OsvVulnerability,
  options: CreateFindingOptions = {}
): SecurityFinding {
  const allIds = new Set<string>();
  if (vuln.id) allIds.add(vuln.id);
  if (Array.isArray(vuln.aliases)) {
    for (const a of vuln.aliases) {
      if (a) allIds.add(a);
    }
  }

  const allIdsList = Array.from(allIds);
  const cveAlias = allIdsList.find((a) => a.toUpperCase().startsWith('CVE-'));
  const vulnerabilityId = cveAlias ?? vuln.id;
  const aliases = allIdsList.filter((a) => a !== vulnerabilityId);

  const { severity, severitySource, cvssVersion, cvssScore, cvssVector } = normalizeSeverity(
    vuln,
    dep.name
  );
  const fixedVersions = extractFixedVersions(vuln, dep.name);
  const { recommendation, details } = computeRemediation(dep.name, dep.version, fixedVersions);

  const titlePrefix = options.isIndeterminate ? '[Indeterminate Match] ' : '';
  const title =
    titlePrefix +
    (vuln.summary?.trim() ||
      vuln.details?.split('\n')[0]?.slice(0, 120)?.trim() ||
      `Vulnerability in ${dep.name}`);

  let description =
    vuln.details?.trim() ||
    vuln.summary?.trim() ||
    (vuln.isIncomplete ? 'Advisory details could not be fully hydrated from OSV.' : 'No advisory details provided.');

  if (options.isIndeterminate && options.indeterminateReason) {
    description += `\n\n[Indeterminate Match Note]: ${options.indeterminateReason}`;
  }

  const references: string[] = [];
  if (Array.isArray(vuln.references)) {
    for (const ref of vuln.references) {
      if (ref?.url && typeof ref.url === 'string') {
        references.push(ref.url);
      }
    }
  }

  const findingId = `dep-${vuln.id}-${dep.name}@${dep.version}-${dep.path.replace(/[^a-zA-Z0-9_-]/g, '_')}`;

  const confidence: 'HIGH' | 'MEDIUM' | 'LOW' = options.isIndeterminate
    ? 'LOW'
    : vuln.isIncomplete
      ? 'MEDIUM'
      : 'HIGH';

  return {
    id: findingId,
    scanner: 'dependency-scanner',
    packageName: dep.name,
    installedVersion: dep.version,
    vulnerabilityId,
    aliases,
    title,
    description,
    severity,
    severitySource,
    cvssVersion,
    cvssScore,
    cvssVector,
    fixedVersions,
    references,
    dependencyType: dep.isDirect ? 'direct' : 'transitive',
    confidence,
    evidence: `Installed at ${dep.path}@${dep.version} (${dep.isDirect ? 'direct' : 'transitive'})`,
    remediation: recommendation,
    remediationDetails: details,
    isIncomplete: vuln.isIncomplete === true,
    isIndeterminate: options.isIndeterminate === true,
    isOptional: dep.isOptional,
    isBundled: dep.isBundled
  };
}

/**
 * Deduplicates findings that represent the same underlying advisory for the same installed package.
 */
export function deduplicateFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const deduped: SecurityFinding[] = [];

  for (const finding of findings) {
    const findingAllIds = new Set([finding.vulnerabilityId, ...finding.aliases]);

    const existing = deduped.find((d) => {
      if (d.evidence !== finding.evidence) return false;
      const dIds = new Set([d.vulnerabilityId, ...d.aliases]);
      for (const id of findingAllIds) {
        if (dIds.has(id)) return true;
      }
      return false;
    });

    if (!existing) {
      deduped.push({
        ...finding,
        aliases: [...finding.aliases],
        references: [...finding.references]
      });
    } else {
      // Merge aliases and references
      for (const alias of finding.aliases) {
        if (!existing.aliases.includes(alias) && existing.vulnerabilityId !== alias) {
          existing.aliases.push(alias);
        }
      }
      for (const ref of finding.references) {
        if (!existing.references.includes(ref)) {
          existing.references.push(ref);
        }
      }
      // Keep higher severity if different
      if (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[existing.severity]) {
        existing.severity = finding.severity;
        if (finding.cvssScore) existing.cvssScore = finding.cvssScore;
        if (finding.cvssVector) existing.cvssVector = finding.cvssVector;
      }
      // If one was incomplete and the other complete, keep the complete details
      if (existing.isIncomplete && !finding.isIncomplete) {
        existing.title = finding.title;
        existing.description = finding.description;
        existing.fixedVersions = finding.fixedVersions;
        existing.remediation = finding.remediation;
        existing.remediationDetails = finding.remediationDetails;
        existing.isIncomplete = false;
      }
    }
  }

  return deduped;
}

/**
 * Safely emits a dependency scanner progress event.
 * Exceptions inside consumer callbacks are caught and swallowed to guarantee
 * scanner stability and accurate exit code execution.
 */
function safeEmitProgress(
  onProgress: ((event: DependencyProgressEvent) => void) | undefined,
  event: DependencyProgressEvent
): void {
  if (!onProgress) return;
  try {
    onProgress(event);
  } catch {
    // Isolated: callback failure must never disrupt scanner or alter findings
  }
}

/**
 * Scans installed npm dependencies for vulnerabilities using package-lock.json and OSV.
 * Read-only and non-destructive.
 */
export async function scanDependencies(
  options: DependencyScanOptions = {}
): Promise<DependencyScanResult> {
  const startTime = Date.now();
  const targetDir = path.resolve(options.cwd ?? process.cwd());

  const severityCounts: Record<SeverityLevel, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MODERATE: 0,
    LOW: 0,
    UNKNOWN: 0
  };

  safeEmitProgress(options.onProgress, {
    stage: 'discovery',
    status: 'started',
    message: 'Locating and parsing lockfile...'
  });

  // 1. Locate and parse lockfile
  const lockfilePath = options.lockfilePath ?? targetDir;
  const parseResult = parsePackageLock(lockfilePath);

  if (!parseResult.success) {
    const durationMs = Date.now() - startTime;
    safeEmitProgress(options.onProgress, {
      stage: 'discovery',
      status: 'failed',
      message: parseResult.error ?? 'Lockfile discovery/parsing failed',
      metadata: {
        errorMessage: parseResult.error,
        durationMs
      }
    });
    safeEmitProgress(options.onProgress, {
      stage: 'completed',
      status: 'failed',
      message: 'Dependency scan failed',
      metadata: {
        totalDependencies: 0,
        errorMessage: parseResult.error,
        durationMs
      }
    });
    return {
      summary: {
        totalDependencies: 0,
        uniquePackages: 0,
        directCount: 0,
        transitiveCount: 0,
        vulnerableDependencies: 0,
        findingsCount: 0,
        severityCounts,
        scanStatus: 'FAILED',
        errorMessage: parseResult.error,
        durationMs
      },
      findings: [],
      dependencies: []
    };
  }

  const dependencies = parseResult.dependencies;
  const uniquePackageNames = new Set(dependencies.map((d) => d.name));

  safeEmitProgress(options.onProgress, {
    stage: 'discovery',
    status: 'completed',
    completed: dependencies.length,
    total: dependencies.length,
    message: `Discovered ${dependencies.length} installed dependencies (${uniquePackageNames.size} unique packages)`,
    metadata: {
      totalDependencies: dependencies.length,
      uniquePackages: uniquePackageNames.size,
      directCount: parseResult.directCount,
      transitiveCount: parseResult.transitiveCount
    }
  });

  // If dependency tree is empty, return clean scan
  if (dependencies.length === 0) {
    const durationMs = Date.now() - startTime;
    safeEmitProgress(options.onProgress, {
      stage: 'completed',
      status: 'completed',
      outcome: 'clean',
      message: 'No dependencies found to scan',
      metadata: {
        totalDependencies: 0,
        uniquePackages: 0,
        directCount: 0,
        transitiveCount: 0,
        findingsCount: 0,
        durationMs
      }
    });
    return {
      summary: {
        totalDependencies: 0,
        uniquePackages: 0,
        directCount: 0,
        transitiveCount: 0,
        vulnerableDependencies: 0,
        findingsCount: 0,
        severityCounts,
        scanStatus: 'CLEAN',
        durationMs
      },
      findings: [],
      dependencies: []
    };
  }

  // 2. Query OSV API and hydrate full advisories
  const osvClient = new OsvClient({
    baseUrl: options.osvBaseUrl,
    timeoutMs: options.timeoutMs,
    batchSize: options.batchSize,
    concurrency: options.concurrency,
    fetchFn: options.fetchFn
  });

  safeEmitProgress(options.onProgress, {
    stage: 'querying',
    status: 'started',
    message: `Querying OSV database for ${uniquePackageNames.size} packages...`,
    metadata: {
      totalDependencies: dependencies.length,
      uniquePackages: uniquePackageNames.size
    }
  });

  let osvResults: Map<string, OsvVulnerability[]>;
  let hasIncompleteAdvisories = false;

  try {
    const queryRes = await osvClient.queryDependencies(dependencies, {
      onBatchProgress: ({ completedBatches, totalBatches, completedQueries, totalQueries }) => {
        safeEmitProgress(options.onProgress, {
          stage: 'querying',
          status: 'progress',
          completed: completedBatches,
          total: totalBatches,
          message: `Querying OSV batches (${completedBatches}/${totalBatches})...`,
          metadata: {
            batchesCompleted: completedBatches,
            totalBatches,
            queriesCompleted: completedQueries,
            totalQueries
          }
        });
      },
      onHydrateProgress: ({ completedAdvisories, totalAdvisories }) => {
        safeEmitProgress(options.onProgress, {
          stage: 'hydrating',
          status: 'progress',
          completed: completedAdvisories,
          total: totalAdvisories,
          message: `Hydrating vulnerability details (${completedAdvisories}/${totalAdvisories})...`,
          metadata: {
            advisoriesHydrated: completedAdvisories,
            totalAdvisories
          }
        });
      }
    });
    osvResults = queryRes.resultsMap;
    hasIncompleteAdvisories = queryRes.hasIncompleteAdvisories;

    safeEmitProgress(options.onProgress, {
      stage: 'querying',
      status: 'completed',
      message: 'OSV querying completed'
    });
  } catch (err) {
    const durationMs = Date.now() - startTime;
    const errMsg = err instanceof Error ? err.message : String(err);
    safeEmitProgress(options.onProgress, {
      stage: 'querying',
      status: 'failed',
      message: errMsg,
      metadata: {
        errorMessage: errMsg,
        durationMs
      }
    });
    safeEmitProgress(options.onProgress, {
      stage: 'completed',
      status: 'failed',
      message: 'Dependency scan failed during OSV query',
      metadata: {
        totalDependencies: dependencies.length,
        errorMessage: errMsg,
        durationMs
      }
    });
    return {
      summary: {
        totalDependencies: dependencies.length,
        uniquePackages: uniquePackageNames.size,
        directCount: parseResult.directCount,
        transitiveCount: parseResult.transitiveCount,
        vulnerableDependencies: 0,
        findingsCount: 0,
        severityCounts,
        scanStatus: 'FAILED',
        errorMessage: errMsg,
        durationMs
      },
      findings: [],
      dependencies
    };
  }

  // 3. Match vulnerabilities to installed instances with Semver Range Validation
  safeEmitProgress(options.onProgress, {
    stage: 'evaluating',
    status: 'started',
    message: 'Evaluating vulnerability ranges and severities...'
  });

  const rawFindings: SecurityFinding[] = [];
  const vulnerablePackageKeys = new Set<string>();

  for (const dep of dependencies) {
    const key = OsvClient.createQueryKey(dep.name, dep.version);
    const candidateVulns = osvResults.get(key) ?? [];

    for (const vuln of candidateVulns) {
      // Find matching affected package entry for this package name
      const matchingAffected = vuln.affected?.find(
        (a) => a.package?.name?.toLowerCase() === dep.name.toLowerCase()
      );

      // Validate version against affected range
      let isConfirmedAffected = true;
      let isIndeterminate = false;
      let indeterminateReason: string | undefined;

      if (matchingAffected) {
        const evalResult = evaluateAffectedStatus(dep.version, matchingAffected);
        if (!evalResult.isAffected) {
          if (evalResult.isIndeterminate) {
            // Indeterminate match: cannot establish confidently, so keep candidate but mark as indeterminate
            isIndeterminate = true;
            indeterminateReason = evalResult.reason;
          } else {
            // Version is explicitly outside the affected range! Do not report false positive!
            isConfirmedAffected = false;
          }
        }
      }

      if (isConfirmedAffected) {
        vulnerablePackageKeys.add(key);
        const finding = createSecurityFinding(dep, vuln, {
          isIndeterminate,
          indeterminateReason
        });
        rawFindings.push(finding);
      }
    }
  }

  // Deduplicate findings
  const findings = deduplicateFindings(rawFindings);

  for (const finding of findings) {
    severityCounts[finding.severity]++;
  }

  // Sort findings by severity descending (CRITICAL -> UNKNOWN)
  findings.sort((a, b) => {
    const diff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (diff !== 0) return diff;
    return a.packageName.localeCompare(b.packageName);
  });

  safeEmitProgress(options.onProgress, {
    stage: 'evaluating',
    status: 'completed',
    message: 'Evaluation completed'
  });

  const durationMs = Date.now() - startTime;
  let scanStatus: 'CLEAN' | 'VULNERABLE' | 'PARTIAL' = 'CLEAN';
  if (findings.length > 0) {
    scanStatus = 'VULNERABLE';
  } else if (hasIncompleteAdvisories) {
    scanStatus = 'PARTIAL';
  }

  const summary: DependencyScanSummary = {
    totalDependencies: dependencies.length,
    uniquePackages: uniquePackageNames.size,
    directCount: parseResult.directCount,
    transitiveCount: parseResult.transitiveCount,
    vulnerableDependencies: vulnerablePackageKeys.size,
    findingsCount: findings.length,
    severityCounts,
    scanStatus,
    hasIncompleteAdvisories,
    durationMs
  };

  const terminalLifecycleStatus: 'completed' | 'partial' =
    scanStatus === 'PARTIAL' ? 'partial' : 'completed';

  const terminalOutcome: 'clean' | 'vulnerable' | undefined =
    findings.length > 0
      ? 'vulnerable'
      : scanStatus === 'PARTIAL'
        ? undefined
        : 'clean';

  safeEmitProgress(options.onProgress, {
    stage: 'completed',
    status: terminalLifecycleStatus,
    outcome: terminalOutcome,
    message: `Scan finished with status: ${scanStatus}`,
    metadata: {
      totalDependencies: dependencies.length,
      uniquePackages: uniquePackageNames.size,
      vulnerableDependencies: vulnerablePackageKeys.size,
      findingsCount: findings.length,
      durationMs
    }
  });

  return {
    summary,
    findings,
    dependencies
  };
}

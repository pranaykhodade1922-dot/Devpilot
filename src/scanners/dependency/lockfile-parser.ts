import fs from 'node:fs';
import path from 'node:path';
import type { InstalledDependency, LockfileParseResult } from './types.js';

interface RawPackageEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  link?: boolean;
  optional?: boolean;
  inBundle?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  [key: string]: unknown;
}

interface RawPackageLock {
  name?: string;
  lockfileVersion?: number;
  packages?: Record<string, RawPackageEntry>;
  dependencies?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Extracts the canonical package name from a lockfile package path or entry.
 */
export function extractPackageName(key: string, entry?: RawPackageEntry): string | null {
  if (entry?.name && typeof entry.name === 'string' && entry.name.trim().length > 0) {
    return entry.name.trim();
  }

  const nmMarker = 'node_modules/';
  const lastIndex = key.lastIndexOf(nmMarker);
  if (lastIndex === -1) {
    return null;
  }

  const candidate = key.slice(lastIndex + nmMarker.length).trim();
  return candidate.length > 0 ? candidate : null;
}

/**
 * Parses package-lock.json (v2 and v3) without modifying files.
 * Accurately handles npm workspaces, local file links, aliases, optional and bundled packages.
 */
export function parsePackageLock(targetDirOrFile: string): LockfileParseResult {
  let resolvedPath = path.resolve(targetDirOrFile);

  // If a directory was provided, resolve to package-lock.json inside it
  if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isDirectory()) {
    resolvedPath = path.join(resolvedPath, 'package-lock.json');
  }

  if (!fs.existsSync(resolvedPath)) {
    return {
      success: false,
      lockfilePath: resolvedPath,
      dependencies: [],
      directCount: 0,
      transitiveCount: 0,
      excludedWorkspaceCount: 0,
      error: `Lockfile not found at ${resolvedPath}`,
      errorCode: 'FILE_NOT_FOUND'
    };
  }

  let rawContent: string;
  try {
    rawContent = fs.readFileSync(resolvedPath, 'utf-8');
  } catch (err) {
    return {
      success: false,
      lockfilePath: resolvedPath,
      dependencies: [],
      directCount: 0,
      transitiveCount: 0,
      excludedWorkspaceCount: 0,
      error: `Failed to read package-lock.json: ${err instanceof Error ? err.message : String(err)}`,
      errorCode: 'FILE_NOT_FOUND'
    };
  }

  let lockData: RawPackageLock;
  try {
    const parsed = JSON.parse(rawContent);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return {
        success: false,
        lockfilePath: resolvedPath,
        dependencies: [],
        directCount: 0,
        transitiveCount: 0,
        excludedWorkspaceCount: 0,
        error: 'package-lock.json is not a valid JSON object',
        errorCode: 'INVALID_JSON'
      };
    }
    lockData = parsed as RawPackageLock;
  } catch (err) {
    return {
      success: false,
      lockfilePath: resolvedPath,
      dependencies: [],
      directCount: 0,
      transitiveCount: 0,
      excludedWorkspaceCount: 0,
      error: `Malformed package-lock.json: ${err instanceof Error ? err.message : String(err)}`,
      errorCode: 'INVALID_JSON'
    };
  }

  const lockfileVersion = lockData.lockfileVersion;
  if (lockfileVersion !== 2 && lockfileVersion !== 3) {
    return {
      success: false,
      lockfilePath: resolvedPath,
      lockfileVersion,
      dependencies: [],
      directCount: 0,
      transitiveCount: 0,
      excludedWorkspaceCount: 0,
      error: `Unsupported package-lock.json version (${String(lockfileVersion)}). DevPilot currently supports lockfileVersion 2 and 3.`,
      errorCode: 'UNSUPPORTED_VERSION'
    };
  }

  const packages = lockData.packages;
  if (!packages || typeof packages !== 'object' || Array.isArray(packages)) {
    return {
      success: false,
      lockfilePath: resolvedPath,
      lockfileVersion,
      dependencies: [],
      directCount: 0,
      transitiveCount: 0,
      excludedWorkspaceCount: 0,
      error: 'package-lock.json is missing a valid "packages" map',
      errorCode: 'UNSUPPORTED_VERSION'
    };
  }

  // Identify direct dependency names declared in the root package
  const rootEntry = packages[''] || packages['.'] || {};
  const directDependencyNames = new Set<string>();

  const collectDirectNames = (depsObj?: Record<string, unknown>) => {
    if (depsObj && typeof depsObj === 'object' && !Array.isArray(depsObj)) {
      for (const [declaredName, versionSpec] of Object.entries(depsObj)) {
        if (declaredName && typeof declaredName === 'string') {
          directDependencyNames.add(declaredName);
          // If npm alias e.g. "my-alias": "npm:react@^18.2.0"
          if (typeof versionSpec === 'string' && versionSpec.startsWith('npm:')) {
            const aliasedPkg = versionSpec.slice(4).split('@')[0];
            if (aliasedPkg) {
              directDependencyNames.add(aliasedPkg);
            }
          }
        }
      }
    }
  };

  collectDirectNames(rootEntry.dependencies as Record<string, unknown> | undefined);
  collectDirectNames(rootEntry.devDependencies as Record<string, unknown> | undefined);
  collectDirectNames(rootEntry.peerDependencies as Record<string, unknown> | undefined);
  collectDirectNames(rootEntry.optionalDependencies as Record<string, unknown> | undefined);

  const dependencies: InstalledDependency[] = [];
  let directCount = 0;
  let transitiveCount = 0;
  let excludedWorkspaceCount = 0;

  for (const [key, entry] of Object.entries(packages)) {
    // Skip the root package itself
    if (key === '' || key === '.') {
      continue;
    }

    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      continue;
    }

    // Filter out internal workspace packages, local links, and file dependencies
    // 1. entry.link === true
    // 2. entry.resolved starts with file: or workspace:
    // 3. key does not contain node_modules/ (e.g. "packages/app-a")
    const isLocalWorkspaceOrLink =
      entry.link === true ||
      (typeof entry.resolved === 'string' &&
        (entry.resolved.startsWith('file:') || entry.resolved.startsWith('workspace:'))) ||
      !key.includes('node_modules/');

    if (isLocalWorkspaceOrLink) {
      excludedWorkspaceCount++;
      continue;
    }

    const pkgName = extractPackageName(key, entry);
    if (!pkgName) {
      continue;
    }

    const version = typeof entry.version === 'string' ? entry.version.trim() : '';
    if (!version) {
      // Missing or invalid package version
      continue;
    }

    // Direct dependency detection:
    // Top-level under root node_modules/ AND declared in root manifest
    const isTopLevelInLockfile =
      key.startsWith('node_modules/') &&
      !key.slice('node_modules/'.length).includes('node_modules/');

    const keyFolder = key.slice('node_modules/'.length);
    const isDirect =
      isTopLevelInLockfile &&
      (directDependencyNames.has(pkgName) || directDependencyNames.has(keyFolder));

    if (isDirect) {
      directCount++;
    } else {
      transitiveCount++;
    }

    dependencies.push({
      name: pkgName,
      version,
      path: key,
      isDirect,
      resolved: typeof entry.resolved === 'string' ? entry.resolved : undefined,
      integrity: typeof entry.integrity === 'string' ? entry.integrity : undefined,
      isOptional: entry.optional === true,
      isBundled: entry.inBundle === true,
      dependencies:
        typeof entry.dependencies === 'object' && entry.dependencies !== null
          ? (entry.dependencies as Record<string, string>)
          : undefined
    });
  }

  return {
    success: true,
    lockfilePath: resolvedPath,
    lockfileVersion,
    dependencies,
    directCount,
    transitiveCount,
    excludedWorkspaceCount
  };
}

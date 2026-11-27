import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

export const CLI_VERSION = '0.1.0';

export interface PackageMetadata {
  version: string;
  name?: string;
  description?: string;
  license?: string;
  repository?: string;
}

/**
 * Returns package metadata dynamically read from the installed package.json.
 */
export function getPackageMetadata(): PackageMetadata {
  try {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    // Check multiple candidate locations for package.json (dev vs dist)
    const candidates = [
      path.resolve(currentDir, '../../package.json'),
      path.resolve(currentDir, '../package.json'),
      path.resolve(currentDir, 'package.json')
    ];

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        const raw = fs.readFileSync(candidate, 'utf-8');
        const parsed = JSON.parse(raw);
        return {
          version: typeof parsed.version === 'string' ? parsed.version : CLI_VERSION,
          name: typeof parsed.name === 'string' ? parsed.name : undefined,
          description: typeof parsed.description === 'string' ? parsed.description : undefined,
          license: typeof parsed.license === 'string' ? parsed.license : undefined,
          repository:
            typeof parsed.repository === 'string'
              ? parsed.repository
              : typeof parsed.repository?.url === 'string'
                ? parsed.repository.url
                : undefined
        };
      }
    }
  } catch {
    // Fall back to CLI_VERSION on any error
  }

  return {
    version: CLI_VERSION
  };
}

/**
 * Returns the current DevPilot version.
 * Dynamically reads from package.json with a fallback to the static CLI_VERSION constant.
 */
export function getDevPilotVersion(): string {
  return getPackageMetadata().version;
}

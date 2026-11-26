import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

export const CLI_VERSION = '0.1.0';

/**
 * Returns the current DevPilot version.
 * Attempts to read dynamically from package.json with a fallback to the static CLI_VERSION constant.
 */
export function getDevPilotVersion(): string {
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
        if (typeof parsed.version === 'string') {
          return parsed.version;
        }
      }
    }
  } catch {
    // Fall back to CLI_VERSION on any error
  }

  return CLI_VERSION;
}

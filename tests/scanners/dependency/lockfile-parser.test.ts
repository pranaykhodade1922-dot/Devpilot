import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  parsePackageLock,
  extractPackageName
} from '../../../src/scanners/dependency/lockfile-parser.js';

describe('Lockfile Parser', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'devpilot-lock-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows
    }
  });

  describe('extractPackageName', () => {
    it('extracts top-level package name', () => {
      expect(extractPackageName('node_modules/express')).toBe('express');
    });

    it('extracts scoped package name', () => {
      expect(extractPackageName('node_modules/@types/node')).toBe('@types/node');
    });

    it('extracts nested package name', () => {
      expect(
        extractPackageName('node_modules/parent/node_modules/child')
      ).toBe('child');
    });

    it('extracts nested scoped package name', () => {
      expect(
        extractPackageName('node_modules/parent/node_modules/@scope/pkg')
      ).toBe('@scope/pkg');
    });

    it('uses entry.name if explicitly provided', () => {
      expect(
        extractPackageName('node_modules/custom-path', { name: 'aliased-pkg' })
      ).toBe('aliased-pkg');
    });
  });

  describe('parsePackageLock', () => {
    it('parses valid npm package-lock v2 with direct and transitive dependencies', () => {
      const lockContent = {
        name: 'test-v2-app',
        lockfileVersion: 2,
        packages: {
          '': {
            name: 'test-v2-app',
            dependencies: {
              express: '^4.18.2'
            },
            devDependencies: {
              typescript: '^5.0.0'
            }
          },
          'node_modules/express': {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            dependencies: {
              accepts: '~1.3.8'
            }
          },
          'node_modules/accepts': {
            version: '1.3.8',
            resolved: 'https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz'
          },
          'node_modules/typescript': {
            version: '5.0.4'
          }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const result = parsePackageLock(tempDir);

      expect(result.success).toBe(true);
      expect(result.lockfileVersion).toBe(2);
      expect(result.dependencies).toHaveLength(3);
      expect(result.directCount).toBe(2);
      expect(result.transitiveCount).toBe(1);

      const expressDep = result.dependencies.find((d) => d.name === 'express');
      expect(expressDep).toBeDefined();
      expect(expressDep?.isDirect).toBe(true);

      const acceptsDep = result.dependencies.find((d) => d.name === 'accepts');
      expect(acceptsDep).toBeDefined();
      expect(acceptsDep?.isDirect).toBe(false);
    });

    it('filters out workspace packages, local links, and file dependencies', () => {
      const lockContent = {
        name: 'workspace-monorepo',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'workspace-monorepo',
            dependencies: {
              'local-lib': 'file:packages/local-lib',
              'npm-lib': '^1.0.0'
            }
          },
          // Workspace internal package entry
          'packages/local-lib': {
            version: '1.0.0'
          },
          // Symlinked workspace dependency in node_modules
          'node_modules/local-lib': {
            resolved: 'packages/local-lib',
            link: true
          },
          // Workspace scheme dependency
          'node_modules/workspace-pkg': {
            version: '1.0.0',
            resolved: 'workspace:packages/workspace-pkg'
          },
          // Legitimate npm dependency
          'node_modules/npm-lib': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/npm-lib/-/npm-lib-1.0.0.tgz'
          }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const result = parsePackageLock(tempDir);

      expect(result.success).toBe(true);
      expect(result.excludedWorkspaceCount).toBe(3); // packages/local-lib, node_modules/local-lib, node_modules/workspace-pkg
      expect(result.dependencies).toHaveLength(1);
      expect(result.dependencies[0]?.name).toBe('npm-lib');
    });

    it('accurately identifies aliased npm dependencies as direct', () => {
      const lockContent = {
        name: 'aliased-app',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'aliased-app',
            dependencies: {
              'my-react': 'npm:react@^18.2.0'
            }
          },
          'node_modules/my-react': {
            name: 'react',
            version: '18.2.0'
          }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const result = parsePackageLock(tempDir);

      expect(result.success).toBe(true);
      expect(result.dependencies).toHaveLength(1);
      expect(result.dependencies[0]?.name).toBe('react');
      expect(result.dependencies[0]?.isDirect).toBe(true);
    });

    it('captures optional and bundled dependency flags', () => {
      const lockContent = {
        name: 'flags-app',
        lockfileVersion: 3,
        packages: {
          '': { name: 'flags-app' },
          'node_modules/opt-dep': {
            version: '1.0.0',
            optional: true
          },
          'node_modules/bundle-dep': {
            version: '2.0.0',
            inBundle: true
          }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const result = parsePackageLock(tempDir);

      const opt = result.dependencies.find((d) => d.name === 'opt-dep');
      expect(opt?.isOptional).toBe(true);

      const bundle = result.dependencies.find((d) => d.name === 'bundle-dep');
      expect(bundle?.isBundled).toBe(true);
    });

    it('handles empty dependency trees gracefully', () => {
      const lockContent = {
        name: 'empty-app',
        lockfileVersion: 3,
        packages: {
          '': { name: 'empty-app' }
        }
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const result = parsePackageLock(tempDir);
      expect(result.dependencies).toHaveLength(0);
    });

    it('returns error when package-lock.json is missing', () => {
      const result = parsePackageLock(tempDir);
      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('FILE_NOT_FOUND');
    });

    it('returns error on malformed JSON', () => {
      fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{"name": "broken", ');
      const result = parsePackageLock(tempDir);
      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('INVALID_JSON');
    });

    it('returns error on unsupported lockfileVersion 1', () => {
      const lockContent = {
        name: 'legacy-app',
        lockfileVersion: 1
      };

      fs.writeFileSync(
        path.join(tempDir, 'package-lock.json'),
        JSON.stringify(lockContent, null, 2)
      );

      const result = parsePackageLock(tempDir);
      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('UNSUPPORTED_VERSION');
    });
  });
});

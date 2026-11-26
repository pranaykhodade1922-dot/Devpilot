import fs from 'node:fs';
import path from 'node:path';

export interface FrameworkSignature {
  name: string;
  dependencies?: readonly string[];
  configFiles?: readonly string[];
  priority?: number;
}

export interface ProjectInfo {
  projectName: string;
  projectRoot: string;
  packageJsonExists: boolean;
  packageManager: string;
  language: 'TypeScript' | 'JavaScript' | 'Unknown';
  framework: string;
  details: {
    isMalformedPackageJson: boolean;
    hasTypeScriptConfig: boolean;
    hasTypeScriptDependency: boolean;
    detectedLockfile: string | null;
  };
}

export interface DetectProjectOptions {
  cwd?: string;
}

/**
 * Known framework definitions ordered by priority.
 * Extensible and not hardcoded to a specific application.
 */
export const KNOWN_FRAMEWORKS: readonly FrameworkSignature[] = [
  // Full-stack / Meta-frameworks (higher priority)
  {
    name: 'Next.js',
    dependencies: ['next'],
    configFiles: ['next.config.js', 'next.config.mjs', 'next.config.ts'],
    priority: 100
  },
  {
    name: 'Nuxt',
    dependencies: ['nuxt', 'nuxt3'],
    configFiles: ['nuxt.config.js', 'nuxt.config.ts'],
    priority: 100
  },
  {
    name: 'SvelteKit',
    dependencies: ['@sveltejs/kit'],
    configFiles: ['svelte.config.js'],
    priority: 100
  },
  {
    name: 'Remix',
    dependencies: ['@remix-run/react', '@remix-run/node'],
    configFiles: ['remix.config.js'],
    priority: 100
  },
  {
    name: 'Astro',
    dependencies: ['astro'],
    configFiles: ['astro.config.mjs', 'astro.config.ts'],
    priority: 100
  },
  {
    name: 'NestJS',
    dependencies: ['@nestjs/core'],
    priority: 90
  },
  // Frontend UI libraries
  {
    name: 'React',
    dependencies: ['react', 'react-dom'],
    priority: 50
  },
  {
    name: 'Vue',
    dependencies: ['vue'],
    priority: 50
  },
  {
    name: 'Angular',
    dependencies: ['@angular/core'],
    configFiles: ['angular.json'],
    priority: 50
  },
  {
    name: 'Svelte',
    dependencies: ['svelte'],
    priority: 50
  },
  {
    name: 'Solid',
    dependencies: ['solid-js'],
    priority: 50
  },
  // Backend / Server frameworks
  {
    name: 'Express',
    dependencies: ['express'],
    priority: 40
  },
  {
    name: 'Fastify',
    dependencies: ['fastify'],
    priority: 40
  },
  {
    name: 'Koa',
    dependencies: ['koa'],
    priority: 40
  },
  {
    name: 'Hono',
    dependencies: ['hono'],
    priority: 40
  }
];

export const LOCKFILE_MAPPING: Record<string, string> = {
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
  'package-lock.json': 'npm',
  'bun.lockb': 'bun',
  'bun.lock': 'bun'
};

/**
 * Detects project configuration, language, package manager, and framework
 * in a target directory without executing commands or modifying files.
 */
export function detectProject(options: DetectProjectOptions = {}): ProjectInfo {
  const targetDir = path.resolve(options.cwd || process.cwd());
  const packageJsonPath = path.join(targetDir, 'package.json');

  let packageJsonExists = false;
  let isMalformedPackageJson = false;
  let packageJsonContent: Record<string, unknown> | null = null;

  if (fs.existsSync(packageJsonPath)) {
    packageJsonExists = true;
    try {
      const raw = fs.readFileSync(packageJsonPath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        packageJsonContent = parsed as Record<string, unknown>;
      } else {
        isMalformedPackageJson = true;
      }
    } catch {
      isMalformedPackageJson = true;
    }
  }

  // 1. Determine Project Name
  let projectName = '';
  if (
    packageJsonContent &&
    typeof packageJsonContent.name === 'string' &&
    packageJsonContent.name.trim().length > 0
  ) {
    projectName = packageJsonContent.name.trim();
  } else {
    // Fall back gracefully to folder name
    projectName = path.basename(targetDir) || 'unnamed-project';
  }

  // 2. Collect dependencies safely
  const dependencies: Record<string, string> = {};
  if (packageJsonContent) {
    const deps = packageJsonContent.dependencies;
    if (typeof deps === 'object' && deps !== null && !Array.isArray(deps)) {
      Object.assign(dependencies, deps);
    }
    const devDeps = packageJsonContent.devDependencies;
    if (typeof devDeps === 'object' && devDeps !== null && !Array.isArray(devDeps)) {
      Object.assign(dependencies, devDeps);
    }
    const peerDeps = packageJsonContent.peerDependencies;
    if (typeof peerDeps === 'object' && peerDeps !== null && !Array.isArray(peerDeps)) {
      Object.assign(dependencies, peerDeps);
    }
  }

  // 3. Detect Package Manager
  let detectedPackageManager = 'None detected';
  let detectedLockfile: string | null = null;

  // Check packageManager field in package.json first (e.g. "packageManager": "pnpm@8.6.0")
  if (
    packageJsonContent &&
    typeof packageJsonContent.packageManager === 'string' &&
    packageJsonContent.packageManager.trim().length > 0
  ) {
    const rawManager = packageJsonContent.packageManager.trim().split('@')[0];
    if (rawManager) {
      detectedPackageManager = rawManager;
    }
  }

  // Check lockfiles in target directory
  if (detectedPackageManager === 'None detected') {
    for (const [lockfile, pm] of Object.entries(LOCKFILE_MAPPING)) {
      if (fs.existsSync(path.join(targetDir, lockfile))) {
        detectedPackageManager = pm;
        detectedLockfile = lockfile;
        break;
      }
    }
  }

  // 4. Detect Language (TypeScript vs JavaScript vs Unknown)
  let hasTypeScriptConfig = false;
  let hasTypeScriptDependency = false;

  // Check for tsconfig*.json
  try {
    const files = fs.readdirSync(targetDir);
    hasTypeScriptConfig = files.some(
      (file) => file === 'tsconfig.json' || /^tsconfig\..*\.json$/.test(file)
    );
  } catch {
    // If directory cannot be read, ignore
  }

  // Check for typescript dependency
  if ('typescript' in dependencies) {
    hasTypeScriptDependency = true;
  }

  // Check for presence of .ts or .tsx files
  let hasTypeScriptFiles = false;
  let hasJavaScriptFiles = false;

  try {
    const checkDirForSourceFiles = (dir: string) => {
      if (!fs.existsSync(dir)) return;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (ext === '.ts' || ext === '.tsx' || ext === '.mts' || ext === '.cts') {
            hasTypeScriptFiles = true;
          } else if (ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') {
            hasJavaScriptFiles = true;
          }
        }
      }
    };

    checkDirForSourceFiles(targetDir);
    checkDirForSourceFiles(path.join(targetDir, 'src'));
  } catch {
    // Ignore read errors
  }

  let language: 'TypeScript' | 'JavaScript' | 'Unknown' = 'Unknown';
  if (hasTypeScriptConfig || hasTypeScriptDependency || hasTypeScriptFiles) {
    language = 'TypeScript';
  } else if (packageJsonExists || hasJavaScriptFiles) {
    language = 'JavaScript';
  }

  // 5. Detect Framework
  let detectedFramework = 'None detected';
  const sortedFrameworks = [...KNOWN_FRAMEWORKS].sort(
    (a, b) => (b.priority ?? 0) - (a.priority ?? 0)
  );

  for (const fw of sortedFrameworks) {
    let matched = false;

    // Check dependencies
    if (fw.dependencies && fw.dependencies.length > 0) {
      if (fw.dependencies.some((dep) => dep in dependencies)) {
        matched = true;
      }
    }

    // Check config files
    if (!matched && fw.configFiles && fw.configFiles.length > 0) {
      for (const configFile of fw.configFiles) {
        if (fs.existsSync(path.join(targetDir, configFile))) {
          matched = true;
          break;
        }
      }
    }

    if (matched) {
      detectedFramework = fw.name;
      break;
    }
  }

  return {
    projectName,
    projectRoot: targetDir,
    packageJsonExists,
    packageManager: detectedPackageManager,
    language,
    framework: detectedFramework,
    details: {
      isMalformedPackageJson,
      hasTypeScriptConfig,
      hasTypeScriptDependency,
      detectedLockfile
    }
  };
}

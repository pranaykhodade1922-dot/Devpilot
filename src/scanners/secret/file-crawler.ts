import fs from 'node:fs';
import path from 'node:path';
import type { SkippedFileRecord } from './types.js';

/**
 * Directories that should be skipped unconditionally by default.
 */
export const DEFAULT_EXCLUDED_DIRECTORIES = new Set([
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.git',
  '.svn',
  '.hg',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache'
]);

/**
 * File extensions that should be skipped as binary or non-text files by default.
 */
export const DEFAULT_EXCLUDED_EXTENSIONS = new Set([
  // Images
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.bmp',
  '.tiff',
  '.webp',
  '.svg',
  // Audio / Video
  '.mp3',
  '.wav',
  '.ogg',
  '.mp4',
  '.mkv',
  '.avi',
  '.mov',
  // Archives
  '.zip',
  '.tar',
  '.gz',
  '.bz2',
  '.7z',
  '.rar',
  // Executables & Binaries
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.bin',
  '.iso',
  // Fonts
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  // Documents & DBs
  '.pdf',
  '.doc',
  '.docx',
  '.sqlite',
  '.db'
]);

export interface FileCrawlerOptions {
  /** Target root directory to scan */
  rootDir: string;
  /** Max file size in bytes (defaults to 2 MB) */
  maxFileSize?: number;
  /** Respect .gitignore rules (defaults to true) */
  respectGitignore?: boolean;
  /** Additional directories to exclude */
  additionalExcludedDirs?: string[];
  /** Follow symlinks (defaults to false for safety against recursion/traversal) */
  followSymlinks?: boolean;
}

export interface CrawlResult {
  /** Files eligible for secret scanning */
  eligibleFiles: string[];
  /** Files intentionally excluded (gitignore, default dirs, extensions) */
  intentionallyExcluded: SkippedFileRecord[];
  /** Files skipped due to errors (too large, unreadable, permission denied, binary) */
  errorSkipped: SkippedFileRecord[];
}

export interface GitignoreRule {
  pattern: string;
  isNegation: boolean;
  isDirOnly: boolean;
  baseDir: string;
  regex: RegExp;
}

/**
 * Converts a gitignore glob pattern to a JavaScript RegExp.
 */
export function parseGitignorePattern(pattern: string, baseDir: string): GitignoreRule | null {
  let line = pattern.trim();

  // Skip comments and blank lines
  if (!line || line.startsWith('#')) {
    return null;
  }

  let isNegation = false;
  if (line.startsWith('!')) {
    isNegation = true;
    line = line.slice(1).trim();
  }

  if (!line) {
    return null;
  }

  let isDirOnly = false;
  if (line.endsWith('/')) {
    isDirOnly = true;
    line = line.slice(0, -1);
  }

  const isLeadingSlash = line.startsWith('/');
  if (isLeadingSlash) {
    line = line.slice(1);
  }

  // Convert gitignore glob wildcards to regex
  // Escape regex specials except * and ?
  let regexStr = '';
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '*') {
      if (line[i + 1] === '*') {
        // ** (match any path segments)
        regexStr += '.*';
        i++;
        if (line[i + 1] === '/') {
          i++; // Skip following slash
        }
      } else {
        // * (match non-slash characters)
        regexStr += '[^/]*';
      }
    } else if (char === '?') {
      regexStr += '[^/]';
    } else if (char === '.') {
      regexStr += '\\.';
    } else if (['\\', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|'].includes(char!)) {
      regexStr += `\\${char}`;
    } else {
      regexStr += char;
    }
  }

  if (isLeadingSlash || line.includes('/')) {
    regexStr = `^${regexStr}(?:/.*)?$`;
  } else {
    regexStr = `(?:^|/)${regexStr}(?:/.*)?$`;
  }

  try {
    const regex = new RegExp(regexStr);
    return {
      pattern,
      isNegation,
      isDirOnly,
      baseDir,
      regex
    };
  } catch {
    return null;
  }
}

/**
 * Loads and parses a .gitignore file if it exists.
 */
export function loadGitignoreFile(gitignorePath: string, baseDir: string): GitignoreRule[] {
  try {
    if (!fs.existsSync(gitignorePath)) {
      return [];
    }
    const content = fs.readFileSync(gitignorePath, 'utf8');
    const lines = content.split(/\r?\n/);
    const rules: GitignoreRule[] = [];

    for (const line of lines) {
      const parsed = parseGitignorePattern(line, baseDir);
      if (parsed) {
        rules.push(parsed);
      }
    }
    return rules;
  } catch {
    return [];
  }
}

/**
 * Checks whether a target path is strictly contained within a root directory.
 * Prevents traversal escapes, prefix collisions (e.g. /root-other), and parent references,
 * while accurately supporting legitimate filenames beginning with '..' (e.g. '..env', '..data.txt').
 */
export function isPathContainedWithin(targetPath: string, rootDir: string): boolean {
  const resolvedTarget = path.resolve(targetPath);
  const resolvedRoot = path.resolve(rootDir);

  const relative = path.relative(resolvedRoot, resolvedTarget);

  if (relative === '') {
    return true;
  }

  if (path.isAbsolute(relative)) {
    return false;
  }

  // Split path into segments using both POSIX and Windows separators
  const firstSegment = relative.split(/[\\/]/)[0];

  // Escaping the root directory produces a first segment of exactly '..'
  return firstSegment !== '..';
}
export function isPathIgnoredByGitignore(
  relPath: string,
  isDir: boolean,
  rules: GitignoreRule[]
): boolean {
  if (rules.length === 0) return false;

  const normalized = relPath.replace(/\\/g, '/');
  let ignored = false;

  for (const rule of rules) {
    if (rule.isDirOnly && !isDir) {
      continue;
    }

    if (rule.regex.test(normalized)) {
      ignored = !rule.isNegation;
    }
  }

  return ignored;
}

/**
 * Checks if a file contains binary content by inspecting its initial byte header.
 * Looks for null bytes (\0) in the first 512 bytes.
 */
export function isBinaryFile(filePath: string): boolean {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(512);
    const bytesRead = fs.readSync(fd, buffer, 0, 512, 0);
    fs.closeSync(fd);

    for (let i = 0; i < bytesRead; i++) {
      if (buffer[i] === 0) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Recursively crawls the target directory and collects eligible text files while
 * tracking intentional exclusions and error skips.
 */
export async function crawlProjectFiles(options: FileCrawlerOptions): Promise<CrawlResult> {
  const rootDir = path.resolve(options.rootDir);
  const maxFileSize = options.maxFileSize ?? 2 * 1024 * 1024; // 2 MB default
  const respectGitignore = options.respectGitignore ?? true;
  const followSymlinks = options.followSymlinks ?? false;

  const excludedDirs = new Set(DEFAULT_EXCLUDED_DIRECTORIES);
  if (options.additionalExcludedDirs) {
    for (const dir of options.additionalExcludedDirs) {
      excludedDirs.add(dir);
    }
  }

  const eligibleFiles: string[] = [];
  const intentionallyExcluded: SkippedFileRecord[] = [];
  const errorSkipped: SkippedFileRecord[] = [];
  const visitedFiles = new Set<string>();

  // Check if rootDir exists and is accessible
  try {
    const rootStat = fs.statSync(rootDir);
    if (!rootStat.isDirectory()) {
      errorSkipped.push({
        filePath: rootDir,
        reason: 'READ_ERROR',
        isIntentionallyExcluded: false,
        details: 'Specified root path is not a directory'
      });
      return { eligibleFiles, intentionallyExcluded, errorSkipped };
    }
  } catch (err) {
    errorSkipped.push({
      filePath: rootDir,
      reason: 'PERMISSION_DENIED',
      isIntentionallyExcluded: false,
      details: err instanceof Error ? err.message : String(err)
    });
    return { eligibleFiles, intentionallyExcluded, errorSkipped };
  }

  // Load root .gitignore
  const gitignoreRules: GitignoreRule[] = [];
  if (respectGitignore) {
    const rootGitignore = path.join(rootDir, '.gitignore');
    gitignoreRules.push(...loadGitignoreFile(rootGitignore, rootDir));
  }

  async function traverse(currentDir: string): Promise<void> {
    // Check if nested .gitignore exists in this directory
    if (respectGitignore && currentDir !== rootDir) {
      const nestedGitignore = path.join(currentDir, '.gitignore');
      if (fs.existsSync(nestedGitignore)) {
        gitignoreRules.push(...loadGitignoreFile(nestedGitignore, currentDir));
      }
    }

    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(currentDir, { withFileTypes: true });
    } catch (err) {
      const relPath = path.relative(rootDir, currentDir) || '.';
      errorSkipped.push({
        filePath: relPath,
        reason: 'PERMISSION_DENIED',
        isIntentionallyExcluded: false,
        details: err instanceof Error ? err.message : String(err)
      });
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(rootDir, fullPath);

      // Traversal safety: prevent traversing outside rootDir using robust relative containment
      if (!isPathContainedWithin(fullPath, rootDir)) {
        intentionallyExcluded.push({
          filePath: relPath,
          reason: 'EXCLUDED_DIRECTORY',
          isIntentionallyExcluded: true,
          details: 'Path traverses outside scan root directory'
        });
        continue;
      }

      // Check symlinks
      if (entry.isSymbolicLink()) {
        if (!followSymlinks) {
          intentionallyExcluded.push({
            filePath: relPath,
            reason: 'EXCLUDED_DIRECTORY',
            isIntentionallyExcluded: true,
            details: 'Symbolic link skipped by policy'
          });
          continue;
        }
      }

      // Directory Handling
      if (entry.isDirectory()) {
        if (excludedDirs.has(entry.name)) {
          intentionallyExcluded.push({
            filePath: relPath,
            reason: 'EXCLUDED_DIRECTORY',
            isIntentionallyExcluded: true,
            details: `Directory matches default exclusion: ${entry.name}`
          });
          continue;
        }

        if (respectGitignore && isPathIgnoredByGitignore(relPath, true, gitignoreRules)) {
          intentionallyExcluded.push({
            filePath: relPath,
            reason: 'GITIGNORE_RULE',
            isIntentionallyExcluded: true,
            details: 'Directory ignored by .gitignore'
          });
          continue;
        }

        await traverse(fullPath);
        continue;
      }

      // File Handling
      if (entry.isFile()) {
        // Prevent duplicate file reads via realpath
        try {
          const real = fs.realpathSync(fullPath);
          if (visitedFiles.has(real)) {
            continue;
          }
          visitedFiles.add(real);
        } catch {
          // If realpath fails, track standard fullPath
          if (visitedFiles.has(fullPath)) {
            continue;
          }
          visitedFiles.add(fullPath);
        }

        // Check gitignore rule
        if (respectGitignore && isPathIgnoredByGitignore(relPath, false, gitignoreRules)) {
          intentionallyExcluded.push({
            filePath: relPath,
            reason: 'GITIGNORE_RULE',
            isIntentionallyExcluded: true,
            details: 'File ignored by .gitignore'
          });
          continue;
        }

        // Check file extension exclusion
        const ext = path.extname(entry.name).toLowerCase();
        if (DEFAULT_EXCLUDED_EXTENSIONS.has(ext)) {
          intentionallyExcluded.push({
            filePath: relPath,
            reason: 'EXCLUDED_EXTENSION',
            isIntentionallyExcluded: true,
            details: `File extension ignored: ${ext}`
          });
          continue;
        }

        // Check file size and readability
        let stat: fs.Stats;
        try {
          stat = await fs.promises.stat(fullPath);
        } catch (err) {
          errorSkipped.push({
            filePath: relPath,
            reason: 'READ_ERROR',
            isIntentionallyExcluded: false,
            details: err instanceof Error ? err.message : String(err)
          });
          continue;
        }

        if (stat.size > maxFileSize) {
          errorSkipped.push({
            filePath: relPath,
            reason: 'TOO_LARGE',
            isIntentionallyExcluded: false,
            details: `File size (${stat.size} bytes) exceeds limit of ${maxFileSize} bytes`
          });
          continue;
        }

        // Check for binary content (intentionally excluded from secret scanning)
        if (isBinaryFile(fullPath)) {
          intentionallyExcluded.push({
            filePath: relPath,
            reason: 'BINARY_FILE',
            isIntentionallyExcluded: true,
            details: 'File contains null bytes (binary content)'
          });
          continue;
        }

        eligibleFiles.push(fullPath);
      }
    }
  }

  await traverse(rootDir);
  return { eligibleFiles, intentionallyExcluded, errorSkipped };
}

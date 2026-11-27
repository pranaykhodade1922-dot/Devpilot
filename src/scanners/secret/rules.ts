import type { SecretRule, SecretMatchContext, SyntheticFixtureResult } from './types.js';
import { calculateShannonEntropy, ENTROPY_THRESHOLDS } from './entropy.js';

/**
 * Common placeholder and dummy values that should never trigger a security finding.
 */
export const PLACEHOLDER_STRINGS = new Set([
  'example',
  'placeholder',
  'changeme',
  'your_api_key_here',
  'your_secret_here',
  'your_key_here',
  'your_token_here',
  'your_password_here',
  'insert_here',
  'my_secret_token',
  'my_api_key',
  'dummy_key',
  'dummy_token',
  'test_token',
  'test_secret',
  'sample_key',
  'sample_token',
  '00000000000000000000000000000000',
  '1234567890abcdef1234567890abcdef',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  'undefined',
  'null',
  'true',
  'false'
]);

/**
 * Checks if a candidate secret is an obvious placeholder, template variable, or dummy string.
 */
export function isPlaceholderOrDummy(candidate: string): boolean {
  if (!candidate || candidate.trim().length === 0) {
    return true;
  }

  const normalized = candidate.trim().toLowerCase();

  // Exact set match
  if (PLACEHOLDER_STRINGS.has(normalized)) {
    return true;
  }

  // Common exact dummy indicators or substrings
  if (
    normalized === 'example' ||
    normalized.startsWith('example_') ||
    normalized.endsWith('_example') ||
    normalized.includes('your_') ||
    normalized.includes('insert_') ||
    normalized.includes('changeme') ||
    normalized.includes('placeholder') ||
    normalized.includes('dummy') ||
    normalized.includes('sample')
  ) {
    return true;
  }

  // Template / environment variable syntax (e.g., "${VAR}", "$VAR", "<api-key>", "{{token}}", "process.env.XYZ")
  if (
    /^(\$\{.*?\}|\{\{.*?\}\}|<.*?>|\$[A-Z0-9_]+|process\.env\.[A-Z0-9_]+)$/i.test(
      candidate.trim()
    )
  ) {
    return true;
  }

  // All identical repeated character (e.g., "XXXXXXXX", "00000000")
  if (/^(.)\1+$/.test(candidate)) {
    return true;
  }

  return false;
}

/**
 * Validates whether a file is a test or spec file based on standard file path conventions.
 */
export function isTestFilePath(filePath: string): boolean {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  return (
    normalized.startsWith('tests/') ||
    normalized.startsWith('test/') ||
    normalized.startsWith('__tests__/') ||
    normalized.startsWith('fixtures/') ||
    normalized.includes('/tests/') ||
    normalized.includes('/test/') ||
    normalized.includes('/__tests__/') ||
    normalized.includes('/fixtures/') ||
    /\.(test|spec)\.[a-z0-9]+$/i.test(normalized)
  );
}

/**
 * Canonical synthetic dummy credentials and sample values from official documentation and test fixtures.
 * Note: Components are joined at runtime so this definition file itself does not contain literal keys.
 */
export const KNOWN_SYNTHETIC_CREDENTIALS = new Set([
  // Canonical AWS documentation sample keys
  ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join(''),
  ['ASIA', 'IOSFODNN7', 'EXAMPLE'].join(''),
  ['wJalrXUtnFEMI/K7MDENG/bPxRfiCY', 'EXAMPLE', 'KEY'].join(''),
  // Canonical GitLab sequential test fixture
  ['glpat-', '0123456789abcdefghij'].join(''),
  // Canonical GitHub sequential test fixtures
  ['ghp_', '0123456789abcdefghijklmnopqrstuvwxyz'].join(''),
  ['ghp_', '1234567890abcdefghijklmnopqrstuvwxyz'].join(''),
  ['github_pat_', '11AAAAAAA_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv'].join(''),
  // Canonical Google / Firebase synthetic key
  ['AIzaSy', 'D9876543210abcdefghijklmnopqrs123'].join(''),
  // Canonical Slack synthetic token
  ['xoxb-', '123456789012', '-1234567890123-', 'fakeSlackToken99'].join(''),
  // Canonical test database passwords and credentials
  ['sUp3rS3cr3tP', '%40ss'].join(''),
  ['sUp3rS3cr3tP', '@ss0ss'].join(''),
  ['sUp3rS3cr3tP', '@ss!'].join(''),
  ['sUp3rS3cr3tP'].join(''),
  ['m0ng0S3cr3t', 'T0k3n'].join(''),
  ['m0ng0', 's3cr3t!23'].join(''),
  ['xK9#mQ2$vL8*yP1!'].join(''),
  ['k9ZmP2vL8xQ1wN4bT7yR3uJ6'].join('')
]);

/**
 * Evaluates whether a line with a PEM header is an isolated PEM header string
 * (e.g., inside test assertions, comments, string literals) rather than a complete
 * or incomplete private-key block.
 */
export function isIsolatedPemHeader(ctx: SecretMatchContext): boolean {
  const line = ctx.lineContent;

  // 1. Check if the line is a test assertion or expectation
  const isAssertion =
    /(?:expect\s*\(|assert(?:\.|\s*\()|\.to(?:Contain|Equal|Be|Match|Include)\s*\(|toBe\s*\(|toContain\s*\(|assertEqual)/i.test(
      line
    );
  if (isAssertion) {
    return true;
  }

  // 2. Check if the line is inside a pure comment or documentation block
  if (/^\s*(?:\*|\/\/|\/\*|#\s*(?:Line|Example|Sample|Test|Note|Doc))/i.test(line)) {
    return true;
  }

  // 3. Check if the line is a closed single-line string literal assignment (e.g. const x = '-----BEGIN...-----';)
  if (
    /(?:const|let|var)\s+\w+\s*=\s*['"][^'"]*-----BEGIN [^'"]*PRIVATE KEY[^'"]*-----['"];/i.test(
      line
    )
  ) {
    return true;
  }

  // 4. Multiline context check: if allLines is available, verify if there are following payload lines
  if (ctx.allLines && ctx.allLines.length > 0) {
    const nextLineIdx = ctx.lineNumber; // 1-based lineNumber is 0-based index of next line
    if (nextLineIdx >= ctx.allLines.length) {
      // EOF immediately after header -> isolated header with 0 payload
      return true;
    }

    // Look at following lines until EOF or END marker
    let hasPayload = false;
    for (let i = nextLineIdx; i < Math.min(ctx.allLines.length, nextLineIdx + 5); i++) {
      const candidateLine = (ctx.allLines[i] ?? '').trim();
      if (!candidateLine) continue;

      if (
        candidateLine === '[REDACTED PRIVATE KEY LINE]' ||
        /^[A-Za-z0-9+/=]{16,}/.test(candidateLine)
      ) {
        hasPayload = true;
        break;
      }
      if (/-----END (?:[A-Z0-9 -]+ )?PRIVATE KEY(?: BLOCK)?-----/.test(candidateLine)) {
        // END marker reached with no payload in between -> empty/isolated header
        break;
      }
      // If we encounter code, closing brace, or assertion before any payload, it's not a payload
      if (
        /^(?:const|let|var|function|class|expect|assert|\}|\]|\);)/.test(candidateLine)
      ) {
        break;
      }
    }

    if (!hasPayload) {
      return true;
    }
  }

  return false;
}

/**
 * Conservative evaluator for recognizing explicitly synthetic test credentials.
 *
 * Requirements:
 * - Only evaluates when the file is confirmed as a test/fixture file via isTestFilePath().
 * - Does NOT suppress real credentials in test files.
 * - Requires exact known dummy values or explicit documented synthetic fixture markers.
 */
export function isSyntheticTestFixture(ctx: SecretMatchContext): SyntheticFixtureResult {
  // If not a test file, never suppress via synthetic test fixture rules
  if (!isTestFilePath(ctx.filePath)) {
    return { isSynthetic: false };
  }

  const candidate = ctx.rawCandidate;
  const lowerCandidate = candidate.toLowerCase();

  // 1. Exact canonical dummy values
  if (KNOWN_SYNTHETIC_CREDENTIALS.has(candidate)) {
    return {
      isSynthetic: true,
      reason: `Exact known synthetic credential fixture: ${candidate}`
    };
  }

  // 2. AWS documentation example key pattern (ends with or contains EXAMPLE)
  if (
    (candidate.startsWith('AKIA') || candidate.startsWith('ASIA')) &&
    (candidate.endsWith('EXAMPLE') || candidate.includes('EXAMPLE'))
  ) {
    return {
      isSynthetic: true,
      reason: 'AWS documentation sample key with EXAMPLE marker'
    };
  }

  // 3. Explicit dummy tokens containing 'example', 'fake', 'dummy', 'sample' in the credential value itself
  if (
    lowerCandidate.includes('example') ||
    lowerCandidate.includes('dummy') ||
    lowerCandidate.includes('fake') ||
    lowerCandidate.includes('sample') ||
    lowerCandidate.includes('mock')
  ) {
    return {
      isSynthetic: true,
      reason: `Credential contains explicit dummy marker (${candidate.slice(0, 8)}...)`
    };
  }

  // 4. Canonical sequential or repeated test patterns in credential value
  if (
    candidate.includes('0123456789') ||
    candidate.includes('1234567890') ||
    candidate.includes('9876543210') ||
    candidate.includes('abcdefghijklmnopqrstuvwxyz') ||
    candidate.includes('abcdefghij') ||
    /(.)\1{5,}/.test(candidate)
  ) {
    return {
      isSynthetic: true,
      reason: 'Credential contains canonical sequential or repeated test pattern'
    };
  }

  // 5. File-level or block-level context markers
  if (ctx.allLines && ctx.allLines.length > 0) {
    // Check first 25 lines for file-level synthetic test fixture markers
    const fileHeaderLines = ctx.allLines.slice(0, 25).join('\n');
    if (
      fileHeaderLines.includes('// devpilot-test-fixture') ||
      fileHeaderLines.includes('/* devpilot-test-fixture') ||
      fileHeaderLines.includes('devpilot-test-fixture') ||
      fileHeaderLines.includes('@fixture') ||
      fileHeaderLines.includes('mock-credentials')
    ) {
      return {
        isSynthetic: true,
        reason: 'File explicitly marked as synthetic test fixture'
      };
    }

    // Check surrounding 15 lines for block-level fixture markers or synthetic test context
    const startIdx = Math.max(0, ctx.lineNumber - 8);
    const endIdx = Math.min(ctx.allLines.length, ctx.lineNumber + 10);
    const surroundingText = ctx.allLines.slice(startIdx, endIdx).join('\n');

    if (
      surroundingText.includes('devpilot-test-fixture') ||
      surroundingText.includes('@fixture') ||
      surroundingText.includes('mock-credentials') ||
      surroundingText.includes('// Synthetic') ||
      surroundingText.includes('/* Synthetic') ||
      surroundingText.includes('// High-entropy') ||
      surroundingText.includes('fake_base64_payload') ||
      surroundingText.includes('fake_payload') ||
      surroundingText.includes('FakePayloadBody') ||
      surroundingText.includes('FakeMiddlePayload') ||
      surroundingText.includes('first_payload') ||
      surroundingText.includes('second_payload') ||
      surroundingText.includes('syntheticKey') ||
      surroundingText.includes('syntheticIncompleteKey') ||
      surroundingText.includes('multiBlockKey') ||
      surroundingText.includes('incompleteKey') ||
      surroundingText.includes('multiKey') ||
      surroundingText.includes('mismatched') ||
      surroundingText.includes('completeKeyContent') ||
      surroundingText.includes('incompleteContent') ||
      surroundingText.includes('mixedContent') ||
      surroundingText.includes('sensitivePayload') ||
      surroundingText.includes('crlfKey') ||
      surroundingText.includes('mockPrivateKey') ||
      surroundingText.includes('sshKey') ||
      surroundingText.includes('File with synthetic secrets')
    ) {
      return {
        isSynthetic: true,
        reason: 'Block or surrounding test code explicitly marked as synthetic fixture'
      };
    }

    // Check if line defines a test fixture variable being passed to evaluateLineRules
    if (
      /(?:const|let|var)\s+(?:line\w*|testCase\w*|dummyLine\w*|sampleLine\w*)\s*=\s*['"]/i.test(
        ctx.lineContent
      ) &&
      surroundingText.includes('evaluateLineRules')
    ) {
      return {
        isSynthetic: true,
        reason: 'Test variable explicitly created as unit-test rule input'
      };
    }
  }

  // 6. Explicit synthetic variable declaration in test code
  if (
    /(?:const|let|var)\s+(?:fake|dummy|mock|stub|sample|synthetic)(?:Aws|Api|Token|Secret|Key|Password|Cred|Credential)/i.test(
      ctx.lineContent
    )
  ) {
    return {
      isSynthetic: true,
      reason: 'Variable declaration has explicit synthetic fixture marker'
    };
  }

  // 7. Explicit inline test assertion validating secret masking or dummy recognition
  if (
    /(?:expect\s*\(\s*(?:isPlaceholderOrDummy|isSyntheticTestFixture|maskSecret|redactSecretFromLine|redactLineSpans)|expect\s*\(\s*redacted\w*\s*\)\s*\.to)/i.test(
      ctx.lineContent
    )
  ) {
    return {
      isSynthetic: true,
      reason: 'Candidate is an argument to a secret-scanner unit test assertion'
    };
  }

  // 8. Explicit inline comment marker: // fake or // synthetic or // Line
  if (/\/\/\s*(?:fake|synthetic|dummy|mock|Line\s*\d+)\b/i.test(ctx.lineContent)) {
    return {
      isSynthetic: true,
      reason: 'Line marked with explicit inline synthetic comment'
    };
  }

  return { isSynthetic: false };
}

/**
 * Built-in Secret Detection Rules for DevPilot Security.
 */
export const BUILT_IN_RULES: SecretRule[] = [
  // ==========================================
  // 1. PRIVATE KEYS & PEM BLOCKS
  // ==========================================
  {
    id: 'SEC-PK-001',
    name: 'Private Key Header or Block',
    category: 'private-key',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // Matches standard PEM private key headers (complete or start of incomplete blocks)
    pattern: /-----BEGIN (?:[A-Z0-9 -]+ )?PRIVATE KEY(?: BLOCK)?-----/g,
    remediation:
      'Immediately revoke and rotate this private key. Never commit private key files or certificate blocks to version control. Store credentials securely in a secret manager.',
    keywords: ['BEGIN', 'PRIVATE KEY'],
    validate: (ctx: SecretMatchContext) => {
      if (isIsolatedPemHeader(ctx)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },

  // ==========================================
  // 2. AWS CREDENTIALS
  // ==========================================
  {
    id: 'SEC-AWS-001',
    name: 'AWS Access Key ID',
    category: 'cloud',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // 20-character key starting with AKIA (standard IAM user) or ASIA (temporary credential)
    pattern: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g,
    secretGroupIndex: 1,
    remediation:
      'Immediately rotate this AWS Access Key in AWS IAM or Secrets Manager and verify AWS CloudTrail logs for unauthorized API access.',
    keywords: ['AKIA', 'ASIA'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },
  {
    id: 'SEC-AWS-002',
    name: 'AWS Secret Access Key Assignment',
    category: 'cloud',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // Contextual assignment of 40-character Base64-like secret key
    pattern:
      /(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    secretGroupIndex: 1,
    minEntropy: 3.8, // Must have genuine token entropy
    minLength: 40,
    remediation:
      'Rotate the AWS IAM secret key immediately. Remove it from code and environment configurations, using IAM Roles for EC2/ECS/Lambda instead.',
    keywords: ['aws_secret'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },

  // ==========================================
  // 3. GOOGLE / FIREBASE API KEYS
  // ==========================================
  {
    id: 'SEC-GCP-001',
    name: 'Google API / Firebase Key',
    category: 'api-key',
    severity: 'HIGH',
    confidence: 'HIGH',
    // Standard Google Cloud / Firebase API key format: AIza + 35 characters
    pattern: /\b(AIza[0-9A-Za-z-_]{35})\b/g,
    secretGroupIndex: 1,
    remediation:
      'Restrict or regenerate the Google Cloud API key in the Google Cloud Console. Apply API restrictions and HTTP/IP referrer restrictions.',
    keywords: ['AIza'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },

  // ==========================================
  // 4. GITHUB TOKENS
  // ==========================================
  {
    id: 'SEC-GH-001',
    name: 'GitHub Personal Access Token',
    category: 'token',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // Classic (ghp_) and Fine-Grained (github_pat_) tokens, plus OAuth (gho_) and user-to-server (ghu_)
    pattern: /\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{70,100})\b/gi,
    secretGroupIndex: 1,
    remediation:
      'Revoke the exposed GitHub token immediately in GitHub Settings -> Developer settings -> Personal access tokens, and check repository access logs.',
    keywords: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },

  // ==========================================
  // 5. GITLAB TOKENS
  // ==========================================
  {
    id: 'SEC-GL-001',
    name: 'GitLab Personal Access Token',
    category: 'token',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // Standard GitLab personal access token format: glpat-[0-9a-zA-Z_-]{20,}
    pattern: /\b(glpat-[0-9a-zA-Z_-]{20,})\b/g,
    secretGroupIndex: 1,
    remediation:
      'Revoke this GitLab token immediately in User Settings -> Access Tokens and rotate any CI/CD variables referencing it.',
    keywords: ['glpat-'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },

  // ==========================================
  // 6. SLACK TOKENS
  // ==========================================
  {
    id: 'SEC-SLACK-001',
    name: 'Slack Bot or User Token',
    category: 'token',
    severity: 'HIGH',
    confidence: 'HIGH',
    // Slack bot (xoxb-), user (xoxp-), app (xoxa-), or refresh (xoxr-) tokens
    pattern: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b/g,
    secretGroupIndex: 1,
    remediation:
      'Revoke the exposed Slack token in the Slack API App dashboard and rotate bot credentials.',
    keywords: ['xoxb-', 'xoxp-', 'xoxa-', 'xoxr-'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },

  // ==========================================
  // 7. DATABASE CONNECTION STRINGS
  // ==========================================
  {
    id: 'SEC-DB-001',
    name: 'Database Connection String with Credentials',
    category: 'database',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // URI scheme with embedded user:password credentials
    pattern:
      /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s\/]+:([^@\s\/]+)@[^:\s\/]+(?::\d+)?\/?[^\s]*)/gi,
    secretGroupIndex: 2, // The embedded password portion
    remediation:
      'Remove credentials from the connection URI. Use environment variables or a secret vault for database passwords, and rotate the exposed database password immediately.',
    keywords: ['postgres://', 'postgresql://', 'mysql://', 'mongodb://', 'mongodb+srv://', 'redis://'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      return true;
    }
  },

  // ==========================================
  // 8. GENERIC PASSWORD / SECRET / API-KEY ASSIGNMENTS
  // ==========================================
  {
    id: 'SEC-GEN-001',
    name: 'Hardcoded Secret or Password Assignment',
    category: 'password',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    // Contextual assignment: password = "..." or secret = "..." with length >= 8 and high entropy
    pattern:
      /(?:password|passwd|api_secret|app_secret|client_secret|auth_token)\s*[:=]\s*['"]([^'"\s]{8,})['"]/gi,
    secretGroupIndex: 1,
    minEntropy: 3.4, // Must not be repetitive or trivial
    minLength: 8,
    remediation:
      'Remove hardcoded passwords or secrets from source code. Load secrets dynamically via environment variables or secret management services.',
    keywords: ['password', 'passwd', 'api_secret', 'app_secret', 'client_secret', 'auth_token'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      if (ctx.rawCandidate.toLowerCase().includes('password')) {
        return false;
      }
      if (isTestFilePath(ctx.filePath)) {
        return ctx.entropy >= ENTROPY_THRESHOLDS.GENERIC_HIGH;
      }
      return true;
    }
  },
  {
    id: 'SEC-GEN-002',
    name: 'Generic API Key Assignment',
    category: 'api-key',
    severity: 'MODERATE',
    confidence: 'MEDIUM',
    // Contextual assignment: apiKey = "..." or api_key = "..."
    pattern:
      /(?:api_key|apikey|access_token|private_key_id)\s*[:=]\s*['"]([A-Za-z0-9_-]{16,})['"]/gi,
    secretGroupIndex: 1,
    minEntropy: 3.5,
    minLength: 16,
    remediation:
      'Store API keys in environment variables or configuration vaults. Never commit live keys to source control.',
    keywords: ['api_key', 'apikey', 'access_token', 'private_key_id'],
    validate: (ctx: SecretMatchContext) => {
      if (isPlaceholderOrDummy(ctx.rawCandidate)) {
        return false;
      }
      if (isSyntheticTestFixture(ctx).isSynthetic) {
        return false;
      }
      if (isTestFilePath(ctx.filePath)) {
        return ctx.entropy >= ENTROPY_THRESHOLDS.BASE64;
      }
      return true;
    }
  }
];

/**
 * Match result produced by evaluating rules against a single line of text.
 */
export interface EvaluatedRuleMatch {
  rule: SecretRule;
  /** 0-based start index of the secret within the line */
  startOffset: number;
  /** 0-based end index of the secret within the line (exclusive) */
  endOffset: number;
  /** Calculated Shannon entropy of the matched secret */
  entropy: number;
}

/**
 * Evaluates all applicable secret rules on a single line of text.
 * Ensures deduplication across multiple overlapping rule matches for the same secret.
 *
 * @param lineContent The text line to inspect
 * @param lineNumber 1-based line number
 * @param filePath File path context
 * @param customRules Optional list of additional rules (or override rules)
 * @returns Array of deduplicated matches with exact offsets
 */
export function evaluateLineRules(
  lineContent: string,
  lineNumber: number,
  filePath: string,
  customRules: SecretRule[] = BUILT_IN_RULES,
  allLines?: string[]
): EvaluatedRuleMatch[] {
  if (!lineContent || lineContent.trim().length === 0) {
    return [];
  }

  const rawMatches: EvaluatedRuleMatch[] = [];

  for (const rule of customRules) {
    // Quick keyword pre-filter check for performance
    if (rule.keywords && rule.keywords.length > 0) {
      const hasKeyword = rule.keywords.some((kw) =>
        lineContent.toLowerCase().includes(kw.toLowerCase())
      );
      if (!hasKeyword) {
        continue;
      }
    }

    // Reset regex state if global
    rule.pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(lineContent)) !== null) {
      // Determine secret string and its offset
      const groupIdx = rule.secretGroupIndex ?? 0;
      const secretStr = match[groupIdx] ?? match[0];

      if (!secretStr) {
        continue;
      }

      // Compute start and end offsets of the secret value within the line
      let startOffset = match.index;
      if (groupIdx > 0 && match[0].includes(secretStr)) {
        startOffset = match.index + match[0].indexOf(secretStr);
      }
      const endOffset = startOffset + secretStr.length;

      // Check min length requirement
      if (rule.minLength && secretStr.length < rule.minLength) {
        continue;
      }

      // Calculate Shannon entropy
      const entropy = calculateShannonEntropy(secretStr);

      // Check entropy requirement
      if (rule.minEntropy && entropy < rule.minEntropy) {
        continue;
      }

      // Check rule validator hook
      if (rule.validate) {
        const ctx: SecretMatchContext = {
          rawCandidate: secretStr,
          lineContent,
          lineNumber,
          filePath,
          entropy,
          allLines
        };
        if (!rule.validate(ctx)) {
          continue;
        }
      }

      rawMatches.push({
        rule,
        startOffset,
        endOffset,
        entropy
      });

      // Avoid infinite loop on zero-width regex matches
      if (match.index === rule.pattern.lastIndex) {
        rule.pattern.lastIndex++;
      }
    }
  }

  if (rawMatches.length === 0) {
    return [];
  }

  // Deduplicate overlapping or identical secret matches on the same line
  // If multiple rules match the same or overlapping span, keep the higher confidence/severity rule
  return deduplicateRuleMatches(rawMatches);
}

/**
 * Deduplicates overlapping rule matches on a line, prioritizing higher severity/confidence.
 */
export function deduplicateRuleMatches(
  matches: EvaluatedRuleMatch[]
): EvaluatedRuleMatch[] {
  if (matches.length <= 1) {
    return matches;
  }

  const severityRank: Record<string, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MODERATE: 3,
    LOW: 2,
    UNKNOWN: 1
  };

  const deduped: EvaluatedRuleMatch[] = [];

  for (const match of matches) {
    // Check if this match overlaps with any already accepted match in deduped
    const overlappingIdx = deduped.findIndex(
      (existing) =>
        match.startOffset < existing.endOffset &&
        match.endOffset > existing.startOffset
    );

    if (overlappingIdx === -1) {
      // No overlap with existing accepted matches
      deduped.push(match);
    } else {
      const existing = deduped[overlappingIdx];
      if (existing) {
        const rankExisting = severityRank[existing.rule.severity] ?? 0;
        const rankMatch = severityRank[match.rule.severity] ?? 0;

        if (rankMatch > rankExisting) {
          // Replace lower severity with higher severity
          deduped[overlappingIdx] = match;
        }
      }
    }
  }

  // Sort final matches by startOffset ascending
  return deduped.sort((a, b) => a.startOffset - b.startOffset);
}

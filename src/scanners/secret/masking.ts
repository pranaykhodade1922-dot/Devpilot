/**
 * Zero-leak secret masking and redaction utilities.
 *
 * CRITICAL SECURITY INVARIANT:
 * Raw secret values MUST NEVER appear in finding evidence, terminal output,
 * logs, JSON reports, or error messages.
 */

/**
 * Masks a single secret string according to length-dependent safety rules.
 *
 * Masking rules:
 * - Empty/null string -> "********"
 * - Length <= 8 characters -> "********" (full redaction to avoid revealing short passwords/PINs)
 * - Length between 9 and 16 characters -> First 2 characters + "****" + last 2 characters
 * - Length > 16 characters -> First 3 characters + "...[REDACTED]..." + last 3 characters
 *
 * @param secret The sensitive candidate secret string
 * @returns A safe, masked representation
 */
export function maskSecret(secret: string): string {
  if (!secret || secret.length === 0) {
    return '********';
  }

  const length = secret.length;

  if (length <= 8) {
    return '********';
  }

  if (length <= 16) {
    const prefix = secret.slice(0, 2);
    const suffix = secret.slice(-2);
    return `${prefix}****${suffix}`;
  }

  // Length > 16
  const prefix = secret.slice(0, 3);
  const suffix = secret.slice(-3);
  return `${prefix}...[REDACTED]...${suffix}`;
}

/**
 * Redacts multiline private-key blocks (both complete and incomplete/unclosed PEM blocks),
 * replacing every sensitive payload line with a redacted placeholder while preserving
 * exact 1:1 original line counts and line numbers.
 *
 * Example:
 * Line 1: -----BEGIN RSA PRIVATE KEY-----
 * Line 2: MIIEowIBAAKCAQEA0Y...
 * Line 3: -----END RSA PRIVATE KEY-----
 *
 * Becomes:
 * Line 1: -----BEGIN RSA PRIVATE KEY-----
 * Line 2: [REDACTED PRIVATE KEY LINE]
 * Line 3: -----END RSA PRIVATE KEY-----
 *
 * If a block is incomplete (no matching END marker before EOF), all subsequent lines
 * are safely redacted to prevent unclosed keys from leaking raw base64 or credential bytes.
 *
 * @param text Multiline content that may contain private keys
 * @returns Text with private key bodies safely redacted and exact line counts preserved
 */
export function redactPrivateKeyBlocks(text: string): string {
  if (!text) return '';

  const isCRLF = text.includes('\r\n');
  const lineEnding = isCRLF ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);

  let inPrivateKeyBlock = false;
  let activeKeyType: string | null = null;
  const resultLines: string[] = [];

  const beginRegex = /-----BEGIN (?:([A-Z0-9 -]+) )?PRIVATE KEY(?: BLOCK)?-----/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';

    if (!inPrivateKeyBlock) {
      const match = beginRegex.exec(line);
      // Ignore isolated PEM header strings in test assertions, comments, or closed single-line literals
      const isAssertionOrComment =
        /(?:expect\s*\(|assert(?:\.|\s*\()|\.to(?:Contain|Equal|Be|Match|Include)\s*\(|toBe\s*\(|toContain\s*\()/i.test(
          line
        ) ||
        /^\s*(?:\*|\/\/|\/\*|#\s*(?:Line|Example|Sample|Test|Note|Doc))/i.test(line) ||
        /(?:const|let|var)\s+\w+\s*=\s*['"][^'"]*-----BEGIN [^'"]*PRIVATE KEY[^'"]*-----['"];/i.test(
          line
        );

      if (match && !isAssertionOrComment) {
        inPrivateKeyBlock = true;
        activeKeyType = match[1] ?? null;
        resultLines.push(line); // Keep header line so detection rules can flag it
      } else {
        resultLines.push(line);
      }
    } else {
      // We are inside a private key block payload
      // Check for matching END marker
      let isEndMarker = false;
      if (activeKeyType) {
        const endRegex = new RegExp(`-----END (?:${activeKeyType} )?PRIVATE KEY(?: BLOCK)?-----`);
        if (endRegex.test(line)) {
          isEndMarker = true;
        }
      } else {
        const genericEndRegex = /-----END (?:[A-Z0-9 -]+ )?PRIVATE KEY(?: BLOCK)?-----/;
        if (genericEndRegex.test(line)) {
          isEndMarker = true;
        }
      }

      if (isEndMarker) {
        inPrivateKeyBlock = false;
        activeKeyType = null;
        resultLines.push(line); // Keep end marker line
      } else {
        // Redact payload line while strictly preserving line count (1 line -> 1 line)
        resultLines.push('[REDACTED PRIVATE KEY LINE]');
      }
    }
  }

  return resultLines.join(lineEnding);
}

/**
 * Span representing a secret's location in a string for multi-token redaction.
 */
export interface SecretSpan {
  start: number;
  end: number;
  replacement?: string;
}

/**
 * Redacts one or more secret spans from a line or text string, correctly handling
 * multiple and overlapping spans without leaking unredacted intermediate characters.
 *
 * @param line The original line of text containing secrets
 * @param spans Array of start/end indices to redact
 * @returns Safe redacted line string
 */
export function redactLineSpans(line: string, spans: SecretSpan[]): string {
  if (!line || spans.length === 0) {
    return line ?? '';
  }

  // Validate and sort spans by start position ascending
  const validSpans = spans
    .filter((s) => s.start >= 0 && s.end > s.start && s.start < line.length)
    .map((s) => ({
      start: Math.max(0, s.start),
      end: Math.min(line.length, s.end),
      replacement: s.replacement
    }))
    .sort((a, b) => a.start - b.start || a.end - b.end);

  if (validSpans.length === 0) {
    return line;
  }

  // Merge overlapping or adjacent spans
  const mergedSpans: SecretSpan[] = [];
  const first = validSpans[0];
  if (!first) {
    return line;
  }

  let current: SecretSpan = first;

  for (let i = 1; i < validSpans.length; i++) {
    const next = validSpans[i];
    if (!next) continue;

    if (next.start <= current.end) {
      // Overlap detected: expand current end to max end
      current = {
        start: current.start,
        end: Math.max(current.end, next.end),
        replacement: current.replacement ?? next.replacement
      };
    } else {
      mergedSpans.push(current);
      current = next;
    }
  }
  mergedSpans.push(current);

  // Construct redacted output string from merged spans
  let result = '';
  let lastIndex = 0;

  for (const span of mergedSpans) {
    result += line.slice(lastIndex, span.start);
    const rawSecret = line.slice(span.start, span.end);
    const masked = span.replacement ?? maskSecret(rawSecret);
    result += masked;
    lastIndex = span.end;
  }

  result += line.slice(lastIndex);
  return result;
}

/**
 * Redacts a candidate secret occurrence from a single line.
 * If start/end column offsets are provided, redacts that exact span;
 * otherwise redacts all occurrences of the candidate string in the line.
 *
 * @param line The original source line
 * @param rawSecret The candidate secret string
 * @param startOffset Optional 0-based start index of secret on the line
 * @param endOffset Optional 0-based end index of secret on the line
 */
export function redactSecretFromLine(
  line: string,
  rawSecret: string,
  startOffset?: number,
  endOffset?: number
): string {
  if (!line || !rawSecret) {
    return line ?? '';
  }

  if (typeof startOffset === 'number' && typeof endOffset === 'number') {
    return redactLineSpans(line, [
      {
        start: startOffset,
        end: endOffset,
        replacement: maskSecret(rawSecret)
      }
    ]);
  }

  // Fallback: replace all occurrences of rawSecret in line
  const masked = maskSecret(rawSecret);
  return line.split(rawSecret).join(masked);
}

const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|messages|rules)/gi,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|messages|rules)/gi,
  /forget\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|messages|rules)/gi,
  /you\s+are\s+now\s+/gi,
  /act\s+as\s+(a|an)\s+/gi,
  /system\s*:\s*/gi,
  /\bassistant\s*:\s*/gi,
  /\bdeveloper\s*:\s*/gi,
  /<\|im_start\|>/gi,
  /<\|im_end\|>/gi,
  /override\s+(the\s+)?(system|previous)/gi,
  /(set|return|give|assign)\s+(the\s+)?(score|security_score|severity)\s+(to|=)\s+/gi,
  /(rate|score)\s+this\s+(as|with)\s+(safe|low|secure|100|10\/10)/gi,
];

export type SanitizeResult = {
  sanitized: string;
  flaggedPatterns: string[];
};

export function sanitizeForPrompt(input: string): SanitizeResult {
  const flagged: string[] = [];
  let sanitized = input;

  for (const pattern of INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(sanitized)) {
      flagged.push(pattern.source);
      sanitized = sanitized.replace(pattern, "[REDACTED:prompt-injection]");
    }
  }

  return { sanitized, flaggedPatterns: flagged };
}

const CONTROL_CHARS = /[\u0000-\u001f\u007f\u2028\u2029]/g;

export type SanitizeMetadataResult = {
  sanitized: string;
  flaggedPatterns: string[];
  hadControlChars: boolean;
};

/**
 * Sanitizes short metadata strings (filename, language hint, etc.) that get
 * embedded inline into LLM prompts. Strips newlines and control characters so
 * an attacker cannot inject a fake "system:" line, then runs the same prompt
 * injection patterns as `sanitizeForPrompt`.
 */
export function sanitizeMetadataForPrompt(
  input: string,
  maxLength: number,
): SanitizeMetadataResult {
  const truncated = input.slice(0, maxLength);
  const stripped = truncated.replace(CONTROL_CHARS, " ").trim();
  const hadControlChars = stripped !== truncated.trim();
  const { sanitized, flaggedPatterns } = sanitizeForPrompt(stripped);
  return { sanitized, flaggedPatterns, hadControlChars };
}

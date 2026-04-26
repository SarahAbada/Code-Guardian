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
    if (pattern.test(sanitized)) {
      flagged.push(pattern.source);
      sanitized = sanitized.replace(pattern, "[REDACTED:prompt-injection]");
    }
    pattern.lastIndex = 0;
  }

  return { sanitized, flaggedPatterns: flagged };
}

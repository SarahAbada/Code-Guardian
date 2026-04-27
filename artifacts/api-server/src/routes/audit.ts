import { Router, type IRouter } from "express";
import { openai } from "@workspace/integrations-openai-ai-server";
import {
  ChatWithAuditBody,
  ChatWithAuditResponse,
  CreateSecurityAuditBody,
  CreateSecurityAuditResponse,
  GetAuditRulesResponse,
} from "@workspace/api-zod";
import { extractJson } from "../lib/llmParsing";

const router: IRouter = Router();

const auditRules = [
  "SQL injection and unsafe query construction",
  "Cross-site scripting and unsafe HTML rendering",
  "Improper authentication and authorization flows",
  "Insecure API endpoint design and missing access controls",
  "Insecure Linux command execution, shell injection, and weak system hardening",
  "Memory leaks, unsafe resource handling, and denial-of-service risks",
  "Secret exposure, unsafe logging, and insecure configuration",
  "Outdated and vulnerable dependencies with known CVEs",
];

const severityRank = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const;

const codeAuditSystemPrompt =
  'You are Sentinel, a senior offensive security researcher. Audit the supplied source code with a strict, paranoid, security-first mindset and return ONLY valid JSON matching exactly this shape: {"summary":"string","severity":"low|medium|high|critical","score":0-100,"hardened":boolean,"badge":"string","mode":"code","vulnerabilities":[{"type":"string","severity":"low|medium|high|critical","line":1,"location":"string","evidence":"string","remediation":"string"}],"secureRewrite":{"vulnerable":"string","hardened":"string","notes":"string"},"checklist":["string"],"attackVector":{"narrative":"string","attackerProfile":"string","steps":["string"],"proofOfConcept":"string","pocLanguage":"string","impact":"string","mitigation":"string"},"dependencies":[]}. ' +
  "Use exact line numbers from the numbered code. Inspect for SQL injection, XSS, broken authentication and authorization, insecure command execution, insecure API surfaces, system hardening problems, memory and DoS risks, and secret exposure. " +
  "STRICT SCORING RUBRIC (apply rigorously, prefer LOWER scores when in doubt): " +
  "- 0-15: ANY critical vulnerability present (RCE, SQL injection, auth bypass, hardcoded prod secrets, command injection). " +
  "- 16-35: ANY high-severity vulnerability present (XSS, missing authentication, insecure deserialization, sensitive data exposure, path traversal). " +
  "- 36-60: ANY medium-severity vulnerability present (weak crypto, missing rate-limiting, verbose errors, weak input validation). " +
  "- 61-80: Only low-severity issues (style/hardening gaps, missing defense-in-depth). " +
  "- 81-100: No vulnerabilities and code follows defense-in-depth practices. " +
  "Be strict, not lenient. If you find even one critical issue the score MUST be 15 or lower regardless of how many other things look fine. " +
  "Always populate attackVector with a realistic exploitation walkthrough for the highest-risk vulnerability detected and a runnable proof-of-concept script (curl, python, javascript, or bash) that demonstrates the exploit against the audited code. pocLanguage must be a single short identifier like 'bash', 'python', 'javascript', 'curl', or 'http'. " +
  "If the code is genuinely clean, set hardened true, badge 'System Hardened', vulnerabilities to [], severity 'low', score 90-100, and the attackVector should describe the most likely theoretical attack a hacker would have attempted plus a defensive PoC showing why it would fail. " +
  "Keep dependencies as an empty array for code mode. Never include any prose outside the JSON.";

const dependencyAuditSystemPrompt =
  'You are Sentinel, a senior supply-chain security researcher. The user pasted a dependency manifest (package.json, requirements.txt, Pipfile, Cargo.toml, go.mod, Gemfile, or similar). Identify each declared dependency and its version, then assess it against well-known public CVEs and security advisories you are confident about. Return ONLY valid JSON matching exactly this shape: {"summary":"string","severity":"low|medium|high|critical","score":0-100,"hardened":boolean,"badge":"string","mode":"dependency","vulnerabilities":[{"type":"string","severity":"low|medium|high|critical","line":1,"location":"string","evidence":"string","remediation":"string"}],"secureRewrite":{"vulnerable":"string","hardened":"string","notes":"string"},"checklist":["string"],"attackVector":{"narrative":"string","attackerProfile":"string","steps":["string"],"proofOfConcept":"string","pocLanguage":"string","impact":"string","mitigation":"string"},"dependencies":[{"name":"string","currentVersion":"string","ecosystem":"npm|pypi|crates|go|rubygems|maven|nuget|other","status":"safe|outdated|vulnerable|unknown","safeVersion":"string","advisory":"string","cves":[{"id":"CVE-YYYY-NNNN","severity":"low|medium|high|critical","description":"string"}]}]}. ' +
  "Every declared dependency MUST appear in the dependencies array exactly once. Mark a dependency 'vulnerable' only when you have high confidence about a real published CVE and include the CVE identifier(s); otherwise use 'outdated', 'safe', or 'unknown' and leave cves as []. Always populate safeVersion with the recommended minimum patched version when status is vulnerable or outdated. " +
  "STRICT SCORING RUBRIC (apply rigorously, prefer LOWER scores when in doubt): " +
  "- 0-15: ANY dependency with a critical CVE present. " +
  "- 16-35: ANY dependency with a high-severity CVE present. " +
  "- 36-60: ANY dependency with a medium CVE OR outdated dependencies with known security fixes. " +
  "- 61-80: Only minor outdated packages with no published CVEs. " +
  "- 81-100: All dependencies are on safe, current, well-maintained versions. " +
  "Be strict, not lenient. One critical CVE caps the score at 15 regardless of how many other deps are clean. " +
  "vulnerabilities[] should mirror the most serious dependency issues, using the manifest line number for each. secureRewrite.vulnerable should be the original manifest, secureRewrite.hardened should be the same manifest with insecure versions bumped to safe versions, notes should explain the upgrades. " +
  "attackVector should describe how a real attacker chains the most severe vulnerable dependency in this manifest into a working exploit, including a runnable PoC (curl, python, javascript, or bash) and a one-word pocLanguage. If everything looks clean, set hardened true, severity 'low', score 90-100, and provide a defensive narrative. Never include any prose outside the JSON.";

const severityScoreCeiling = {
  critical: 15,
  high: 35,
  medium: 60,
  low: 80,
} as const;

function enforceStrictScore(
  modelScore: number,
  highestSeverity: "low" | "medium" | "high" | "critical",
  vulnerabilityCount: number,
  dependencyHasCriticalCve: boolean,
  dependencyHasHighCve: boolean,
  dependencyHasIssue: boolean,
  hardened: boolean,
): number {
  const sanitized = Math.min(Math.max(Math.round(modelScore), 0), 100);

  if (hardened) {
    return Math.max(sanitized, 85);
  }

  let ceiling = 100;

  if (vulnerabilityCount > 0) {
    ceiling = Math.min(ceiling, severityScoreCeiling[highestSeverity]);
  }

  if (dependencyHasCriticalCve) {
    ceiling = Math.min(ceiling, severityScoreCeiling.critical);
  } else if (dependencyHasHighCve) {
    ceiling = Math.min(ceiling, severityScoreCeiling.high);
  } else if (dependencyHasIssue) {
    ceiling = Math.min(ceiling, severityScoreCeiling.medium);
  }

  if (vulnerabilityCount >= 5) {
    ceiling = Math.max(0, ceiling - 5);
  }
  if (vulnerabilityCount >= 10) {
    ceiling = Math.max(0, ceiling - 5);
  }

  return Math.min(sanitized, ceiling);
}

function normalizeAuditResult(
  raw: unknown,
  code: string,
  mode: "code" | "dependency",
) {
  const lineCount = Math.max(code.split(/\r?\n/).length, 1);
  const draft =
    raw && typeof raw === "object"
      ? { mode, ...(raw as Record<string, unknown>) }
      : raw;
  const parsed = CreateSecurityAuditResponse.parse(draft);
  const vulnerabilities = parsed.vulnerabilities.map((vulnerability) => ({
    ...vulnerability,
    line: Math.min(Math.max(Math.round(vulnerability.line), 1), lineCount),
  }));
  const highestSeverity = vulnerabilities.reduce<
    "low" | "medium" | "high" | "critical"
  >(
    (highest, vulnerability) =>
      severityRank[vulnerability.severity] > severityRank[highest]
        ? vulnerability.severity
        : highest,
    "low",
  );
  const dependencies = parsed.dependencies ?? [];
  const dependencyHasIssue = dependencies.some(
    (dep) => dep.status === "vulnerable" || dep.status === "outdated",
  );
  const dependencyHasCriticalCve = dependencies.some((dep) =>
    (dep.cves ?? []).some((cve) => cve.severity === "critical"),
  );
  const dependencyHasHighCve = dependencies.some((dep) =>
    (dep.cves ?? []).some((cve) => cve.severity === "high"),
  );
  const hardened = vulnerabilities.length === 0 && !dependencyHasIssue;

  const finalSeverity: "low" | "medium" | "high" | "critical" = hardened
    ? "low"
    : dependencyHasCriticalCve
      ? "critical"
      : dependencyHasHighCve && severityRank[highestSeverity] < severityRank.high
        ? "high"
        : highestSeverity;

  const enforcedScore = enforceStrictScore(
    parsed.score,
    finalSeverity,
    vulnerabilities.length,
    dependencyHasCriticalCve,
    dependencyHasHighCve,
    dependencyHasIssue,
    hardened,
  );

  return CreateSecurityAuditResponse.parse({
    ...parsed,
    mode,
    vulnerabilities,
    severity: finalSeverity,
    score: enforcedScore,
    hardened,
    badge: hardened ? "System Hardened" : parsed.badge,
    secureRewrite: {
      vulnerable: parsed.secureRewrite.vulnerable || code,
      hardened: parsed.secureRewrite.hardened || code,
      notes: parsed.secureRewrite.notes,
    },
    dependencies,
  });
}

router.get("/audit-rules", (_req, res) => {
  res.json(GetAuditRulesResponse.parse({ rules: auditRules }));
});

router.post("/audits", async (req, res) => {
  const validation = CreateSecurityAuditBody.safeParse(req.body);

  if (!validation.success) {
    res
      .status(400)
      .json({ message: "Provide a code snippet up to 20,000 characters." });
    return;
  }

  const { code, language, mode: requestedMode } = validation.data;
  const mode: "code" | "dependency" = requestedMode === "dependency" ? "dependency" : "code";
  const numberedCode = code
    .split(/\r?\n/)
    .map((line, index) => `${index + 1}: ${line}`)
    .join("\n");

  const systemPrompt =
    mode === "dependency" ? dependencyAuditSystemPrompt : codeAuditSystemPrompt;
  const userLabel =
    mode === "dependency" ? "Numbered manifest" : "Numbered code";

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-5.2",
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: systemPrompt },
        {
          role: "user",
          content: `Mode: ${mode}\nLanguage hint: ${
            language || "unknown"
          }\n\n${userLabel}:\n${numberedCode}`,
        },
      ],
    });

    const content = completion.choices[0]?.message?.content;

    if (!content) {
      throw new Error("The model returned an empty audit.");
    }

    const result = normalizeAuditResult(extractJson(content), code, mode);
    res.json(result);
  } catch (error) {
    if (error instanceof Error && error.name === "ZodError") {
      req.log.error({ err: error }, "Audit response validation failed");
      res
        .status(500)
        .json({ message: "Sentinel could not validate the audit response." });
      return;
    }

    req.log.error({ err: error }, "Security audit failed");
    res.status(500).json({ message: "Sentinel audit failed. Please try again." });
  }
});

const chatSystemPrompt =
  "You are Sentinel, a senior security researcher continuing a conversation about a specific code or dependency audit you just produced. " +
  "Stay strictly grounded in the supplied audit context: cite specific line numbers, vulnerabilities, dependencies, and CVEs when relevant. " +
  "Answer concisely (under 280 words unless asked otherwise), use plain text or fenced code blocks when showing code, and never invent vulnerabilities or CVEs that are not in the supplied context. " +
  "If the user asks for an alternative fix, prefer dependency-free standard library solutions when they ask for that. " +
  "If a question falls outside the audit, say so briefly and steer back to the audit.";

function buildContextPreamble(
  context: ReturnType<typeof ChatWithAuditBody.parse>["context"],
) {
  const parts: string[] = [];
  parts.push(`Audit mode: ${context.mode ?? "code"}`);
  if (context.language) parts.push(`Language hint: ${context.language}`);
  if (context.summary) parts.push(`Audit summary: ${context.summary}`);

  if (context.vulnerabilities && context.vulnerabilities.length > 0) {
    const lines = context.vulnerabilities
      .map(
        (v, idx) =>
          `${idx + 1}. [${v.severity.toUpperCase()}] ${v.type} @ line ${v.line} (${v.location})\n   evidence: ${v.evidence}\n   remediation: ${v.remediation}`,
      )
      .join("\n");
    parts.push(`Detected vulnerabilities:\n${lines}`);
  } else {
    parts.push("Detected vulnerabilities: none");
  }

  if (context.dependencies && context.dependencies.length > 0) {
    const lines = context.dependencies
      .map((d) => {
        const cveLine =
          d.cves && d.cves.length > 0
            ? d.cves
                .map(
                  (c) => `${c.id} [${c.severity}] ${c.description}`,
                )
                .join("; ")
            : "none";
        return `- ${d.name}@${d.currentVersion} (${d.ecosystem}) status=${d.status}${
          d.safeVersion ? ` safeVersion=${d.safeVersion}` : ""
        } cves=${cveLine}`;
      })
      .join("\n");
    parts.push(`Dependency findings:\n${lines}`);
  }

  const numberedCode = context.code
    .split(/\r?\n/)
    .map((line, index) => `${index + 1}: ${line}`)
    .join("\n");
  parts.push(`Audited source (numbered):\n${numberedCode}`);

  return parts.join("\n\n");
}

router.post("/audits/chat", async (req, res) => {
  const validation = ChatWithAuditBody.safeParse(req.body);

  if (!validation.success) {
    res.status(400).json({ message: "Invalid chat request." });
    return;
  }

  const { messages, context } = validation.data;

  try {
    const preamble = buildContextPreamble(context);
    const completion = await openai.chat.completions.create({
      model: "gpt-5.2",
      messages: [
        { role: "system", content: chatSystemPrompt },
        {
          role: "system",
          content: `Audit context follows. Use it to ground every answer.\n\n${preamble}`,
        },
        ...messages.map((m) => ({ role: m.role, content: m.content })),
      ],
    });

    const reply = completion.choices[0]?.message?.content?.trim();
    if (!reply) {
      throw new Error("The model returned an empty chat reply.");
    }

    res.json(ChatWithAuditResponse.parse({ reply }));
  } catch (error) {
    if (error instanceof Error && error.name === "ZodError") {
      req.log.error({ err: error }, "Chat response validation failed");
      res
        .status(500)
        .json({ message: "Sentinel could not validate the chat reply." });
      return;
    }

    req.log.error({ err: error }, "Sentinel chat failed");
    res.status(500).json({ message: "Sentinel chat failed. Please try again." });
  }
});

export default router;

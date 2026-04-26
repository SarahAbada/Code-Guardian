import { Router, type IRouter } from "express";
import { openai } from "@workspace/integrations-openai-ai-server";
import {
  ChatWithAuditBody,
  ChatWithAuditResponse,
  CreateSecurityAuditBody,
  CreateSecurityAuditResponse,
  GetAuditRulesResponse,
} from "@workspace/api-zod";

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

function extractJson(content: string) {
  const trimmed = content.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    return JSON.parse(trimmed);
  }

  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");

  if (start === -1 || end === -1 || end <= start) {
    throw new Error("The model did not return a JSON object.");
  }

  return JSON.parse(trimmed.slice(start, end + 1));
}

const codeAuditSystemPrompt =
  'You are Sentinel, a senior offensive security researcher. Audit the supplied source code with a security-first mindset and return ONLY valid JSON matching exactly this shape: {"summary":"string","severity":"low|medium|high|critical","score":0-100,"hardened":boolean,"badge":"string","mode":"code","vulnerabilities":[{"type":"string","severity":"low|medium|high|critical","line":1,"location":"string","evidence":"string","remediation":"string"}],"secureRewrite":{"vulnerable":"string","hardened":"string","notes":"string"},"checklist":["string"],"attackVector":{"narrative":"string","attackerProfile":"string","steps":["string"],"proofOfConcept":"string","pocLanguage":"string","impact":"string","mitigation":"string"},"dependencies":[]}. ' +
  "Use exact line numbers from the numbered code. Inspect for SQL injection, XSS, broken authentication and authorization, insecure command execution, insecure API surfaces, system hardening problems, memory and DoS risks, and secret exposure. " +
  "Always populate attackVector with a realistic exploitation walkthrough for the highest-risk vulnerability detected and a runnable proof-of-concept script (curl, python, javascript, or bash) that demonstrates the exploit against the audited code. pocLanguage must be a single short identifier like 'bash', 'python', 'javascript', 'curl', or 'http'. " +
  "If the code is clean, set hardened true, badge 'System Hardened', vulnerabilities to [], severity 'low', and the attackVector should describe the most likely theoretical attack a hacker would have attempted plus a defensive PoC showing why it would fail. " +
  "Keep dependencies as an empty array for code mode. Never include any prose outside the JSON.";

const dependencyAuditSystemPrompt =
  'You are Sentinel, a senior supply-chain security researcher. The user pasted a dependency manifest (package.json, requirements.txt, Pipfile, Cargo.toml, go.mod, Gemfile, or similar). Identify each declared dependency and its version, then assess it against well-known public CVEs and security advisories you are confident about. Return ONLY valid JSON matching exactly this shape: {"summary":"string","severity":"low|medium|high|critical","score":0-100,"hardened":boolean,"badge":"string","mode":"dependency","vulnerabilities":[{"type":"string","severity":"low|medium|high|critical","line":1,"location":"string","evidence":"string","remediation":"string"}],"secureRewrite":{"vulnerable":"string","hardened":"string","notes":"string"},"checklist":["string"],"attackVector":{"narrative":"string","attackerProfile":"string","steps":["string"],"proofOfConcept":"string","pocLanguage":"string","impact":"string","mitigation":"string"},"dependencies":[{"name":"string","currentVersion":"string","ecosystem":"npm|pypi|crates|go|rubygems|maven|nuget|other","status":"safe|outdated|vulnerable|unknown","safeVersion":"string","advisory":"string","cves":[{"id":"CVE-YYYY-NNNN","severity":"low|medium|high|critical","description":"string"}]}]}. ' +
  "Every declared dependency MUST appear in the dependencies array exactly once. Mark a dependency 'vulnerable' only when you have high confidence about a real published CVE and include the CVE identifier(s); otherwise use 'outdated', 'safe', or 'unknown' and leave cves as []. Always populate safeVersion with the recommended minimum patched version when status is vulnerable or outdated. " +
  "vulnerabilities[] should mirror the most serious dependency issues, using the manifest line number for each. secureRewrite.vulnerable should be the original manifest, secureRewrite.hardened should be the same manifest with insecure versions bumped to safe versions, notes should explain the upgrades. " +
  "attackVector should describe how a real attacker chains the most severe vulnerable dependency in this manifest into a working exploit, including a runnable PoC (curl, python, javascript, or bash) and a one-word pocLanguage. If everything looks clean, set hardened true, severity 'low', and provide a defensive narrative. Never include any prose outside the JSON.";

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
    parsed.severity,
  );
  const dependencyHasIssue = (parsed.dependencies ?? []).some(
    (dep) => dep.status === "vulnerable" || dep.status === "outdated",
  );
  const hardened = vulnerabilities.length === 0 && !dependencyHasIssue;

  return CreateSecurityAuditResponse.parse({
    ...parsed,
    mode,
    vulnerabilities,
    severity: hardened ? "low" : highestSeverity,
    score: Math.min(Math.max(Math.round(parsed.score), 0), 100),
    hardened,
    badge: hardened ? "System Hardened" : parsed.badge,
    secureRewrite: {
      vulnerable: parsed.secureRewrite.vulnerable || code,
      hardened: parsed.secureRewrite.hardened || code,
      notes: parsed.secureRewrite.notes,
    },
    dependencies: parsed.dependencies ?? [],
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

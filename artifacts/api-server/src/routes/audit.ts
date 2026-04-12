import { Router, type IRouter } from "express";
import { openai } from "@workspace/integrations-openai-ai-server";
import {
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

function normalizeAuditResult(raw: unknown, code: string) {
  const lineCount = Math.max(code.split(/\r?\n/).length, 1);
  const parsed = CreateSecurityAuditResponse.parse(raw);
  const vulnerabilities = parsed.vulnerabilities.map((vulnerability) => ({
    ...vulnerability,
    line: Math.min(Math.max(Math.round(vulnerability.line), 1), lineCount),
  }));
  const highestSeverity =
    vulnerabilities.reduce<"low" | "medium" | "high" | "critical">(
      (highest, vulnerability) =>
        severityRank[vulnerability.severity] > severityRank[highest]
          ? vulnerability.severity
          : highest,
      parsed.severity,
    );
  const hardened = vulnerabilities.length === 0;

  return CreateSecurityAuditResponse.parse({
    ...parsed,
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
  });
}

router.get("/audit-rules", (_req, res) => {
  res.json(GetAuditRulesResponse.parse({ rules: auditRules }));
});

router.post("/audits", async (req, res) => {
  const validation = CreateSecurityAuditBody.safeParse(req.body);

  if (!validation.success) {
    res.status(400).json({ message: "Provide a code snippet up to 20,000 characters." });
    return;
  }

  const { code, language } = validation.data;
  const numberedCode = code
    .split(/\r?\n/)
    .map((line, index) => `${index + 1}: ${line}`)
    .join("\n");

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-5.2",
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You are Sentinel, a senior security researcher. Audit code with a security-first mindset. Return only valid JSON matching this shape: {\"summary\":\"string\",\"severity\":\"low|medium|high|critical\",\"score\":0-100,\"hardened\":boolean,\"badge\":\"string\",\"vulnerabilities\":[{\"type\":\"string\",\"severity\":\"low|medium|high|critical\",\"line\":1,\"location\":\"string\",\"evidence\":\"string\",\"remediation\":\"string\"}],\"secureRewrite\":{\"vulnerable\":\"string\",\"hardened\":\"string\",\"notes\":\"string\"},\"checklist\":[\"string\"]}. Include exact line numbers from the numbered code. Check for SQL injection, XSS, improper authentication flows, insecure Linux command execution, insecure API endpoints, system hardening problems, memory leaks, secret exposure, and denial-of-service risks. Be specific and actionable. If the code is clean, set hardened true, badge to System Hardened, vulnerabilities to an empty array, severity low, and provide a brief hardened rewrite or the original code with hardening notes.",
        },
        {
          role: "user",
          content: `Language hint: ${language || "unknown"}\n\nNumbered code:\n${numberedCode}`,
        },
      ],
    });

    const content = completion.choices[0]?.message?.content;

    if (!content) {
      throw new Error("The model returned an empty audit.");
    }

    const result = normalizeAuditResult(extractJson(content), code);
    res.json(result);
  } catch (error) {
    if (error instanceof Error && error.name === "ZodError") {
      req.log.error({ err: error }, "Audit response validation failed");
      res.status(500).json({ message: "Sentinel could not validate the audit response." });
      return;
    }

    req.log.error({ err: error }, "Security audit failed");
    res.status(500).json({ message: "Sentinel audit failed. Please try again." });
  }
});

export default router;
import React, { useMemo, useRef, useState, useEffect } from "react";
import {
  useCreateSecurityAudit,
  useGetAuditRules,
  useChatWithAudit,
} from "@workspace/api-client-react";
import type {
  SecurityAuditRequest,
  SecurityAuditResult,
  DependencyFinding,
  AuditChatMessage,
} from "@workspace/api-client-react/src/generated/api.schemas";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Terminal,
  Activity,
  Loader2,
  ArrowRight,
  ShieldBan,
  Lock,
  TerminalSquare,
  Search,
  CheckCircle,
  Code2,
  Package,
  Crosshair,
  MessageSquare,
  Send,
  User,
  Bot,
  Bug,
  Skull,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

type Mode = "code" | "dependency";

type ChatTurn = AuditChatMessage;

const CODE_PLACEHOLDER = `// Paste raw logic here for deep inspection...
// Example:
// app.get('/user', (req, res) => {
//   db.query('SELECT * FROM users WHERE id = ' + req.query.id);
// });`;

const DEPENDENCY_PLACEHOLDER = `# Paste a manifest: package.json, requirements.txt, Cargo.toml...
# Example (requirements.txt):
# Django==2.2.4
# requests==2.19.1
# Pillow==5.4.1`;

export default function Home() {
  const [mode, setMode] = useState<Mode>("code");
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("");
  const [auditResult, setAuditResult] = useState<SecurityAuditResult | null>(
    null,
  );
  const [auditedCode, setAuditedCode] = useState("");
  const [auditedLanguage, setAuditedLanguage] = useState<string | undefined>(
    undefined,
  );
  const [chatMessages, setChatMessages] = useState<ChatTurn[]>([]);
  const [chatInput, setChatInput] = useState("");
  const chatScrollRef = useRef<HTMLDivElement | null>(null);

  const { data: auditRulesData, isLoading: isLoadingRules } =
    useGetAuditRules();
  const createAuditMutation = useCreateSecurityAudit();
  const chatMutation = useChatWithAudit();
  const { toast } = useToast();

  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages, chatMutation.isPending]);

  const handleAudit = () => {
    if (!code.trim()) {
      toast({
        title: "Error",
        description:
          mode === "dependency"
            ? "Paste a manifest file (package.json, requirements.txt, Cargo.toml) to audit."
            : "Please provide code to audit.",
        variant: "destructive",
      });
      return;
    }

    const payload: SecurityAuditRequest = { code, mode };
    if (language.trim()) {
      payload.language = language.trim();
    }

    createAuditMutation.mutate(
      { data: payload },
      {
        onSuccess: (result) => {
          setAuditResult(result);
          setAuditedCode(code);
          setAuditedLanguage(language.trim() || undefined);
          setChatMessages([]);
          setChatInput("");
          toast({
            title: "Audit Complete",
            description: "Scan finished successfully.",
          });
        },
        onError: (err) => {
          toast({
            title: "Audit Failed",
            description:
              (err as Error)?.message || "Failed to complete security audit.",
            variant: "destructive",
          });
        },
      },
    );
  };

  const handleSendChat = () => {
    const trimmed = chatInput.trim();
    if (!trimmed || !auditResult) return;

    const nextMessages: ChatTurn[] = [
      ...chatMessages,
      { role: "user", content: trimmed },
    ];
    setChatMessages(nextMessages);
    setChatInput("");

    chatMutation.mutate(
      {
        data: {
          messages: nextMessages,
          context: {
            code: auditedCode,
            language: auditedLanguage,
            mode: auditResult.mode,
            summary: auditResult.summary,
            vulnerabilities: auditResult.vulnerabilities,
            dependencies: auditResult.dependencies,
          },
        },
      },
      {
        onSuccess: (result) => {
          setChatMessages((prev) => [
            ...prev,
            { role: "assistant", content: result.reply },
          ]);
        },
        onError: (err) => {
          toast({
            title: "Chat Failed",
            description:
              (err as Error)?.message || "Sentinel could not reply.",
            variant: "destructive",
          });
          setChatMessages((prev) => prev.slice(0, -1));
          setChatInput(trimmed);
        },
      },
    );
  };

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case "critical":
        return "text-red-500 border-red-500 bg-red-500/10";
      case "high":
        return "text-orange-500 border-orange-500 bg-orange-500/10";
      case "medium":
        return "text-yellow-500 border-yellow-500 bg-yellow-500/10";
      case "low":
        return "text-blue-500 border-blue-500 bg-blue-500/10";
      default:
        return "text-primary border-primary bg-primary/10";
    }
  };

  const getDependencyStatusColor = (status: DependencyFinding["status"]) => {
    switch (status) {
      case "vulnerable":
        return "text-red-500 border-red-500 bg-red-500/10";
      case "outdated":
        return "text-yellow-500 border-yellow-500 bg-yellow-500/10";
      case "safe":
        return "text-primary border-primary bg-primary/10";
      default:
        return "text-primary/60 border-primary/40 bg-primary/5";
    }
  };

  const dependencies = useMemo(
    () => auditResult?.dependencies ?? [],
    [auditResult],
  );

  const vulnerableDepCount = dependencies.filter(
    (d) => d.status === "vulnerable",
  ).length;
  const outdatedDepCount = dependencies.filter(
    (d) => d.status === "outdated",
  ).length;

  return (
    <div className="min-h-screen bg-background text-primary font-mono flex flex-col items-center p-4 md:p-8">
      <div className="w-full max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <header className="flex items-center justify-between border-b border-border pb-4 mb-8">
          <div className="flex items-center gap-3">
            <TerminalSquare className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-bold tracking-widest uppercase">
              SENTINEL_OS
            </h1>
          </div>
          <div className="flex items-center gap-2 text-sm text-primary/70">
            <Activity className="w-4 h-4 animate-pulse" />
            <span>SEC_LOGIC_AUDITOR :: ONLINE</span>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column - Input */}
          <div className="space-y-6">
            <Card className="border-border bg-card rounded-none shadow-none">
              <CardHeader className="border-b border-border bg-secondary/30 rounded-none pb-4">
                <CardTitle className="text-sm font-bold flex items-center gap-2 uppercase tracking-widest text-primary">
                  <Terminal className="w-4 h-4" />
                  {mode === "code" ? "Target Code Input" : "Manifest Input"}
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 space-y-4">
                {/* Mode Toggle */}
                <div className="space-y-2">
                  <label className="text-xs text-primary/70 uppercase">
                    Scan Mode
                  </label>
                  <div className="grid grid-cols-2 border border-border">
                    <button
                      type="button"
                      onClick={() => setMode("code")}
                      data-testid="mode-code"
                      className={`flex items-center justify-center gap-2 py-2 text-xs uppercase tracking-widest transition-colors ${
                        mode === "code"
                          ? "bg-primary text-primary-foreground"
                          : "text-primary/70 hover:bg-primary/10"
                      }`}
                    >
                      <Code2 className="w-3 h-3" />
                      Code Audit
                    </button>
                    <button
                      type="button"
                      onClick={() => setMode("dependency")}
                      data-testid="mode-dependency"
                      className={`flex items-center justify-center gap-2 py-2 text-xs uppercase tracking-widest transition-colors border-l border-border ${
                        mode === "dependency"
                          ? "bg-primary text-primary-foreground"
                          : "text-primary/70 hover:bg-primary/10"
                      }`}
                    >
                      <Package className="w-3 h-3" />
                      Dependency Audit
                    </button>
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-xs text-primary/70 uppercase">
                    {mode === "code"
                      ? "Language Hint (Optional)"
                      : "Manifest Type (Optional)"}
                  </label>
                  <Input
                    placeholder={
                      mode === "code"
                        ? "e.g. typescript, python, go"
                        : "e.g. package.json, requirements.txt, Cargo.toml"
                    }
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    data-testid="input-language"
                    className="rounded-none border-border bg-background focus-visible:ring-1 focus-visible:ring-primary font-mono text-sm"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs text-primary/70 uppercase">
                    {mode === "code" ? "Source Code" : "Manifest Contents"}
                  </label>
                  <Textarea
                    placeholder={
                      mode === "code"
                        ? CODE_PLACEHOLDER
                        : DEPENDENCY_PLACEHOLDER
                    }
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    data-testid="input-code"
                    className="min-h-[400px] rounded-none border-border bg-background focus-visible:ring-1 focus-visible:ring-primary font-mono text-sm resize-y"
                    spellCheck={false}
                  />
                </div>
                <Button
                  onClick={handleAudit}
                  disabled={createAuditMutation.isPending}
                  data-testid="button-audit"
                  className="w-full rounded-none font-bold tracking-widest uppercase border border-primary hover:bg-primary hover:text-primary-foreground transition-colors group"
                >
                  {createAuditMutation.isPending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      INITIATING SCAN_SEQUENCE...
                    </>
                  ) : (
                    <>
                      <Search className="mr-2 h-4 w-4 group-hover:animate-pulse" />
                      {mode === "code"
                        ? "EXECUTE SECURITY AUDIT"
                        : "EXECUTE DEPENDENCY SCAN"}
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Audit Rules Display */}
            <Card className="border-border bg-card rounded-none shadow-none">
              <CardHeader className="border-b border-border bg-secondary/30 rounded-none pb-3">
                <CardTitle className="text-xs font-bold uppercase tracking-widest text-primary/80">
                  Active Analysis Rulesets
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4">
                {isLoadingRules ? (
                  <div className="text-sm text-primary/50 animate-pulse">
                    Loading rulesets...
                  </div>
                ) : auditRulesData?.rules ? (
                  <ul className="text-xs space-y-2 text-primary/70">
                    {auditRulesData.rules.map((rule, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <ArrowRight className="w-3 h-3 mt-0.5 shrink-0" />
                        <span>{rule}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-xs text-primary/50">
                    No rulesets loaded.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right Column - Results */}
          <div className="space-y-6">
            {!auditResult ? (
              <div className="h-full min-h-[500px] border border-dashed border-border flex flex-col items-center justify-center text-primary/30 p-8 text-center bg-card/20">
                <Shield className="w-16 h-16 mb-4 opacity-50" />
                <p className="text-sm tracking-widest uppercase">
                  AWAITING TARGET PAYLOAD
                </p>
                <p className="text-xs mt-2 max-w-xs">
                  System standing by to analyze code for logic flaws,
                  vulnerabilities, and hardening opportunities.
                </p>
              </div>
            ) : (
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                {/* Result Summary */}
                <Card className="border-border bg-card rounded-none shadow-none">
                  <CardHeader className="border-b border-border pb-4 bg-secondary/20">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <CardTitle className="text-lg font-bold uppercase tracking-widest flex items-center gap-2">
                          {auditResult.mode === "dependency" ? (
                            <Package className="w-4 h-4" />
                          ) : (
                            <Code2 className="w-4 h-4" />
                          )}
                          {auditResult.mode === "dependency"
                            ? "Dependency Report"
                            : "Audit Report"}
                        </CardTitle>
                        <CardDescription
                          data-testid="text-summary"
                          className="text-primary/70 font-mono mt-1 text-xs"
                        >
                          {auditResult.summary}
                        </CardDescription>
                      </div>
                      <Badge
                        variant="outline"
                        data-testid="badge-severity"
                        className={`rounded-none border uppercase tracking-wider text-xs py-1 px-2 shrink-0 ${getSeverityColor(
                          auditResult.severity,
                        )}`}
                      >
                        {auditResult.severity} RISK
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="p-4 flex flex-col gap-4">
                    <div className="flex justify-between items-center bg-background border border-border p-4">
                      <div className="text-sm uppercase text-primary/70">
                        Security Score
                      </div>
                      <div
                        className="text-2xl font-bold"
                        data-testid="text-score"
                      >
                        {auditResult.score}/100
                      </div>
                    </div>

                    {auditResult.hardened ||
                    (auditResult.vulnerabilities.length === 0 &&
                      vulnerableDepCount === 0 &&
                      outdatedDepCount === 0) ? (
                      <div className="flex items-center gap-3 bg-primary/10 border border-primary text-primary p-4">
                        <ShieldCheck className="w-6 h-6" />
                        <div>
                          <h4 className="font-bold uppercase tracking-wider">
                            System Hardened
                          </h4>
                          <p className="text-xs opacity-80">
                            {auditResult.badge ||
                              "No critical vulnerabilities detected in this payload."}
                          </p>
                        </div>
                      </div>
                    ) : null}
                  </CardContent>
                </Card>

                {/* Tabs: Findings | Attack Vector | Dependencies | Hardened */}
                <Tabs defaultValue="findings" className="w-full">
                  <TabsList className="w-full grid grid-cols-4 rounded-none bg-secondary/30 border border-border p-0 h-auto">
                    <TabsTrigger
                      value="findings"
                      data-testid="tab-findings"
                      className="rounded-none data-[state=active]:bg-primary data-[state=active]:text-primary-foreground text-xs uppercase tracking-widest py-2"
                    >
                      <ShieldAlert className="w-3 h-3 mr-1.5" />
                      Findings ({auditResult.vulnerabilities.length})
                    </TabsTrigger>
                    <TabsTrigger
                      value="attack"
                      data-testid="tab-attack"
                      className="rounded-none data-[state=active]:bg-primary data-[state=active]:text-primary-foreground text-xs uppercase tracking-widest py-2"
                    >
                      <Crosshair className="w-3 h-3 mr-1.5" />
                      Attack Vector
                    </TabsTrigger>
                    <TabsTrigger
                      value="dependencies"
                      data-testid="tab-dependencies"
                      className="rounded-none data-[state=active]:bg-primary data-[state=active]:text-primary-foreground text-xs uppercase tracking-widest py-2"
                    >
                      <Package className="w-3 h-3 mr-1.5" />
                      Deps ({dependencies.length})
                    </TabsTrigger>
                    <TabsTrigger
                      value="hardened"
                      data-testid="tab-hardened"
                      className="rounded-none data-[state=active]:bg-primary data-[state=active]:text-primary-foreground text-xs uppercase tracking-widest py-2"
                    >
                      <Lock className="w-3 h-3 mr-1.5" />
                      Hardened
                    </TabsTrigger>
                  </TabsList>

                  {/* FINDINGS TAB */}
                  <TabsContent value="findings" className="mt-4 space-y-4">
                    {auditResult.vulnerabilities.length > 0 ? (
                      <div className="space-y-4">
                        <h3 className="text-sm font-bold uppercase tracking-widest border-b border-border pb-2 flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-red-500" />
                          Detected Anomalies (
                          {auditResult.vulnerabilities.length})
                        </h3>
                        <div className="space-y-4">
                          {auditResult.vulnerabilities.map((vuln, idx) => (
                            <Card
                              key={idx}
                              data-testid={`card-vuln-${idx}`}
                              className="border-border bg-card rounded-none shadow-none overflow-hidden"
                            >
                              <div
                                className={`h-1 w-full ${getSeverityColor(
                                  vuln.severity,
                                )
                                  .split(" ")[0]
                                  .replace("text-", "bg-")}`}
                              />
                              <CardContent className="p-4 space-y-3">
                                <div className="flex items-start justify-between">
                                  <div className="flex items-center gap-2">
                                    <AlertTriangle
                                      className={`w-4 h-4 ${
                                        getSeverityColor(vuln.severity).split(
                                          " ",
                                        )[0]
                                      }`}
                                    />
                                    <span className="font-bold text-sm uppercase">
                                      {vuln.type}
                                    </span>
                                  </div>
                                  <Badge
                                    variant="outline"
                                    className={`rounded-none text-[10px] ${getSeverityColor(
                                      vuln.severity,
                                    )}`}
                                  >
                                    L:{vuln.line}
                                  </Badge>
                                </div>
                                <div className="bg-background border border-border p-2 text-xs font-mono text-primary/80 overflow-x-auto">
                                  <span className="text-primary/50 select-none mr-2">
                                    {String(vuln.line).padStart(3, " ")} |
                                  </span>
                                  {vuln.evidence}
                                </div>
                                <div className="text-xs text-primary/70 pl-2 border-l-2 border-primary/30">
                                  <span className="font-bold text-primary mr-1">
                                    Remediation:
                                  </span>
                                  {vuln.remediation}
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>

                        {auditResult.checklist &&
                          auditResult.checklist.length > 0 && (
                            <Card className="border-border bg-card rounded-none shadow-none mt-6">
                              <CardHeader className="border-b border-border pb-3">
                                <CardTitle className="text-sm font-bold uppercase tracking-widest">
                                  Security Checklist
                                </CardTitle>
                              </CardHeader>
                              <CardContent className="p-4">
                                <ul className="space-y-2 text-xs">
                                  {auditResult.checklist.map((item, idx) => (
                                    <li
                                      key={idx}
                                      className="flex items-start gap-2"
                                    >
                                      <CheckCircle className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                                      <span className="text-primary/80">
                                        {item}
                                      </span>
                                    </li>
                                  ))}
                                </ul>
                              </CardContent>
                            </Card>
                          )}
                      </div>
                    ) : (
                      <div className="border border-border bg-card p-6 text-xs text-primary/70 flex items-center gap-3">
                        <ShieldCheck className="w-5 h-5 text-primary" />
                        No code-level anomalies detected. Review the dependency
                        and attack-vector tabs for additional context.
                      </div>
                    )}
                  </TabsContent>

                  {/* ATTACK VECTOR TAB */}
                  <TabsContent value="attack" className="mt-4">
                    {auditResult.attackVector ? (
                      <Card
                        data-testid="card-attack-vector"
                        className="border-border bg-card rounded-none shadow-none"
                      >
                        <CardHeader className="border-b border-border pb-3 bg-red-500/5">
                          <CardTitle className="text-sm font-bold uppercase tracking-widest flex items-center gap-2 text-red-500">
                            <Crosshair className="w-4 h-4" />
                            Attack Vector Walkthrough
                          </CardTitle>
                          <CardDescription className="text-xs text-primary/70 font-mono mt-1">
                            How a hacker would weaponize the detected
                            vulnerabilities.
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="p-4 space-y-4">
                          <div className="border border-border bg-background p-3 text-xs flex items-start gap-2">
                            <Skull className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
                            <div>
                              <div className="text-[10px] uppercase tracking-widest text-primary/60 mb-1">
                                Attacker Profile
                              </div>
                              <div className="text-primary/90">
                                {auditResult.attackVector.attackerProfile}
                              </div>
                            </div>
                          </div>

                          <div>
                            <div className="text-[10px] uppercase tracking-widest text-primary/60 mb-2">
                              Exploit Narrative
                            </div>
                            <p className="text-xs text-primary/80 leading-relaxed whitespace-pre-wrap">
                              {auditResult.attackVector.narrative}
                            </p>
                          </div>

                          {auditResult.attackVector.steps &&
                            auditResult.attackVector.steps.length > 0 && (
                              <div>
                                <div className="text-[10px] uppercase tracking-widest text-primary/60 mb-2">
                                  Kill Chain
                                </div>
                                <ol className="space-y-1.5 text-xs text-primary/80">
                                  {auditResult.attackVector.steps.map(
                                    (step, idx) => (
                                      <li
                                        key={idx}
                                        className="flex gap-2"
                                      >
                                        <span className="text-red-500 font-bold shrink-0">
                                          {String(idx + 1).padStart(2, "0")}.
                                        </span>
                                        <span>{step}</span>
                                      </li>
                                    ),
                                  )}
                                </ol>
                              </div>
                            )}

                          <div>
                            <div className="flex items-center justify-between mb-2">
                              <div className="text-[10px] uppercase tracking-widest text-primary/60 flex items-center gap-1.5">
                                <Bug className="w-3 h-3" />
                                Proof of Concept
                              </div>
                              <Badge
                                variant="outline"
                                className="rounded-none text-[10px] border-red-500 text-red-500 bg-red-500/5"
                              >
                                {auditResult.attackVector.pocLanguage}
                              </Badge>
                            </div>
                            <pre
                              data-testid="text-poc"
                              className="text-xs overflow-x-auto bg-black border border-red-500/40 p-3 text-red-300 whitespace-pre-wrap"
                            >
                              {auditResult.attackVector.proofOfConcept}
                            </pre>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div className="border border-border bg-background p-3">
                              <div className="text-[10px] uppercase tracking-widest text-red-500 mb-1">
                                Impact
                              </div>
                              <div className="text-xs text-primary/80">
                                {auditResult.attackVector.impact}
                              </div>
                            </div>
                            <div className="border border-primary/40 bg-primary/5 p-3">
                              <div className="text-[10px] uppercase tracking-widest text-primary mb-1">
                                Mitigation
                              </div>
                              <div className="text-xs text-primary/80">
                                {auditResult.attackVector.mitigation}
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ) : (
                      <div className="border border-border bg-card p-6 text-xs text-primary/70">
                        No attack vector available for this scan.
                      </div>
                    )}
                  </TabsContent>

                  {/* DEPENDENCIES TAB */}
                  <TabsContent value="dependencies" className="mt-4">
                    {dependencies.length > 0 ? (
                      <div className="space-y-3">
                        <div className="flex items-center gap-3 text-[10px] uppercase tracking-widest text-primary/60 border-b border-border pb-2">
                          <span>Total: {dependencies.length}</span>
                          <span className="text-red-500">
                            Vulnerable: {vulnerableDepCount}
                          </span>
                          <span className="text-yellow-500">
                            Outdated: {outdatedDepCount}
                          </span>
                        </div>
                        {dependencies.map((dep, idx) => (
                          <Card
                            key={`${dep.name}-${idx}`}
                            data-testid={`card-dep-${idx}`}
                            className="border-border bg-card rounded-none shadow-none"
                          >
                            <CardContent className="p-3 space-y-2">
                              <div className="flex items-center justify-between flex-wrap gap-2">
                                <div className="flex items-center gap-2 min-w-0">
                                  <Package className="w-4 h-4 text-primary/70 shrink-0" />
                                  <span className="font-bold text-sm truncate">
                                    {dep.name}
                                  </span>
                                  <span
                                    className={`text-xs ${
                                      dep.status === "vulnerable"
                                        ? "text-red-500 font-bold"
                                        : dep.status === "outdated"
                                          ? "text-yellow-500"
                                          : "text-primary/70"
                                    }`}
                                  >
                                    @{dep.currentVersion}
                                  </span>
                                  <span className="text-[10px] text-primary/40 uppercase">
                                    [{dep.ecosystem}]
                                  </span>
                                </div>
                                <Badge
                                  variant="outline"
                                  className={`rounded-none text-[10px] uppercase ${getDependencyStatusColor(
                                    dep.status,
                                  )}`}
                                >
                                  {dep.status}
                                </Badge>
                              </div>

                              {dep.safeVersion && (
                                <div className="text-xs flex items-center gap-2 pl-6">
                                  <ArrowRight className="w-3 h-3 text-primary" />
                                  <span className="text-primary/60">
                                    Safe version:
                                  </span>
                                  <span className="text-primary font-bold">
                                    {dep.safeVersion}
                                  </span>
                                </div>
                              )}

                              {dep.cves && dep.cves.length > 0 && (
                                <div className="pl-6 space-y-1.5">
                                  {dep.cves.map((cve, cveIdx) => (
                                    <div
                                      key={cveIdx}
                                      className="text-xs border-l-2 border-red-500/40 pl-2"
                                    >
                                      <div className="flex items-center gap-2">
                                        <Badge
                                          variant="outline"
                                          className={`rounded-none text-[10px] ${getSeverityColor(
                                            cve.severity,
                                          )}`}
                                        >
                                          {cve.id}
                                        </Badge>
                                        <span className="text-[10px] uppercase text-primary/60">
                                          {cve.severity}
                                        </span>
                                      </div>
                                      <div className="text-primary/70 mt-0.5">
                                        {cve.description}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}

                              {dep.advisory && (
                                <div className="text-[11px] text-primary/60 pl-6 italic">
                                  {dep.advisory}
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    ) : (
                      <div className="border border-border bg-card p-6 text-xs text-primary/70 flex items-center gap-3">
                        <Package className="w-5 h-5" />
                        No dependency data for this scan. Switch to Dependency
                        Audit mode and paste a manifest file to scan for CVEs.
                      </div>
                    )}
                  </TabsContent>

                  {/* HARDENED TAB */}
                  <TabsContent value="hardened" className="mt-4">
                    {auditResult.secureRewrite ? (
                      <Card className="border-border bg-card rounded-none shadow-none">
                        <CardHeader className="border-b border-border pb-3 bg-secondary/30">
                          <CardTitle className="text-sm font-bold uppercase tracking-widest flex items-center gap-2">
                            <Lock className="w-4 h-4" />
                            Hardened Rewrite
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="p-0">
                          <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border">
                            <div className="p-4 bg-background/50">
                              <div className="text-[10px] text-red-500 uppercase tracking-widest mb-2 font-bold flex items-center gap-1">
                                <ShieldBan className="w-3 h-3" /> Vulnerable
                                Origin
                              </div>
                              <pre className="text-xs overflow-x-auto text-primary/70 whitespace-pre-wrap">
                                {auditResult.secureRewrite.vulnerable}
                              </pre>
                            </div>
                            <div className="p-4 bg-primary/5">
                              <div className="text-[10px] text-primary uppercase tracking-widest mb-2 font-bold flex items-center gap-1">
                                <ShieldCheck className="w-3 h-3" /> Hardened
                                Target
                              </div>
                              <pre className="text-xs overflow-x-auto text-primary font-bold whitespace-pre-wrap">
                                {auditResult.secureRewrite.hardened}
                              </pre>
                            </div>
                          </div>
                          <div className="p-4 border-t border-border text-xs text-primary/70 bg-secondary/20">
                            <span className="font-bold text-primary mr-1">
                              ANALYSIS NOTES:
                            </span>
                            {auditResult.secureRewrite.notes}
                          </div>
                        </CardContent>
                      </Card>
                    ) : (
                      <div className="border border-border bg-card p-6 text-xs text-primary/70">
                        No hardened rewrite available.
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </div>
            )}
          </div>
        </div>

        {/* CHAT PANEL */}
        {auditResult && (
          <Card
            data-testid="card-chat"
            className="border-border bg-card rounded-none shadow-none"
          >
            <CardHeader className="border-b border-border pb-3 bg-secondary/30">
              <CardTitle className="text-sm font-bold uppercase tracking-widest flex items-center gap-2">
                <MessageSquare className="w-4 h-4" />
                Sentinel Console
              </CardTitle>
              <CardDescription className="text-xs text-primary/60 font-mono mt-1">
                Ask follow-up questions about this scan. Sentinel is grounded in
                the audit context above.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div
                ref={chatScrollRef}
                data-testid="chat-scroll"
                className="max-h-[400px] min-h-[180px] overflow-y-auto p-4 space-y-3 bg-background/40"
              >
                {chatMessages.length === 0 && !chatMutation.isPending && (
                  <div className="text-xs text-primary/50 italic space-y-1">
                    <div>
                      &gt; Try: "Why is line{" "}
                      {auditResult.vulnerabilities[0]?.line ?? "X"} a risk?"
                    </div>
                    <div>
                      &gt; Try: "Give me an alternative fix that doesn't use
                      external libraries."
                    </div>
                    {auditResult.mode === "dependency" && (
                      <div>
                        &gt; Try: "What's the upgrade path for the most
                        critical dependency?"
                      </div>
                    )}
                  </div>
                )}

                {chatMessages.map((msg, idx) => (
                  <div
                    key={idx}
                    data-testid={`chat-msg-${idx}`}
                    className={`flex gap-2 ${
                      msg.role === "user" ? "justify-end" : "justify-start"
                    }`}
                  >
                    {msg.role === "assistant" && (
                      <div className="w-6 h-6 border border-primary/40 flex items-center justify-center shrink-0 bg-primary/10">
                        <Bot className="w-3.5 h-3.5 text-primary" />
                      </div>
                    )}
                    <div
                      className={`max-w-[80%] text-xs px-3 py-2 border whitespace-pre-wrap font-mono ${
                        msg.role === "user"
                          ? "bg-primary/10 border-primary/40 text-primary"
                          : "bg-background border-border text-primary/80"
                      }`}
                    >
                      {msg.content}
                    </div>
                    {msg.role === "user" && (
                      <div className="w-6 h-6 border border-primary/40 flex items-center justify-center shrink-0 bg-primary/10">
                        <User className="w-3.5 h-3.5 text-primary" />
                      </div>
                    )}
                  </div>
                ))}

                {chatMutation.isPending && (
                  <div className="flex gap-2 justify-start">
                    <div className="w-6 h-6 border border-primary/40 flex items-center justify-center shrink-0 bg-primary/10">
                      <Bot className="w-3.5 h-3.5 text-primary animate-pulse" />
                    </div>
                    <div className="text-xs px-3 py-2 border border-border bg-background text-primary/60 italic flex items-center gap-2">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Sentinel is analyzing...
                    </div>
                  </div>
                )}
              </div>

              <div className="border-t border-border p-3 bg-background flex items-end gap-2">
                <span className="text-primary/60 text-xs pt-2 select-none">
                  &gt;
                </span>
                <Textarea
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      handleSendChat();
                    }
                  }}
                  placeholder="Ask a follow-up about this scan..."
                  data-testid="input-chat"
                  className="min-h-[40px] max-h-[120px] rounded-none border-border bg-background focus-visible:ring-1 focus-visible:ring-primary font-mono text-xs resize-y flex-1"
                  spellCheck={false}
                  disabled={chatMutation.isPending}
                />
                <Button
                  onClick={handleSendChat}
                  disabled={chatMutation.isPending || !chatInput.trim()}
                  data-testid="button-chat-send"
                  className="rounded-none border border-primary hover:bg-primary hover:text-primary-foreground"
                  variant="ghost"
                >
                  <Send className="w-4 h-4" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

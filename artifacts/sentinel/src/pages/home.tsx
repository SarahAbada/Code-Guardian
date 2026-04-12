import React, { useState } from "react";
import { useCreateSecurityAudit, useGetAuditRules } from "@workspace/api-client-react";
import type { SecurityAuditRequest, SecurityAuditResult } from "@workspace/api-client-react/src/generated/api.schemas";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, Terminal, Activity, Loader2, ArrowRight, ShieldBan, Lock, TerminalSquare, Search, CheckCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Home() {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("");
  const [auditResult, setAuditResult] = useState<SecurityAuditResult | null>(null);
  
  const { data: auditRulesData, isLoading: isLoadingRules } = useGetAuditRules();
  const createAuditMutation = useCreateSecurityAudit();
  const { toast } = useToast();

  const handleAudit = () => {
    if (!code.trim()) {
      toast({
        title: "Error",
        description: "Please provide code to audit.",
        variant: "destructive"
      });
      return;
    }

    const payload: SecurityAuditRequest = { code };
    if (language.trim()) {
      payload.language = language.trim();
    }

    createAuditMutation.mutate(
      { data: payload },
      {
        onSuccess: (result) => {
          setAuditResult(result);
          toast({
            title: "Audit Complete",
            description: "Scan finished successfully.",
          });
        },
        onError: (err) => {
          toast({
            title: "Audit Failed",
            description: err?.message || "Failed to complete security audit.",
            variant: "destructive"
          });
        }
      }
    );
  };

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case "critical": return "text-red-500 border-red-500 bg-red-500/10";
      case "high": return "text-orange-500 border-orange-500 bg-orange-500/10";
      case "medium": return "text-yellow-500 border-yellow-500 bg-yellow-500/10";
      case "low": return "text-blue-500 border-blue-500 bg-blue-500/10";
      default: return "text-primary border-primary bg-primary/10";
    }
  };

  return (
    <div className="min-h-screen bg-background text-primary font-mono flex flex-col items-center p-4 md:p-8">
      <div className="w-full max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <header className="flex items-center justify-between border-b border-border pb-4 mb-8">
          <div className="flex items-center gap-3">
            <TerminalSquare className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-bold tracking-widest uppercase">SENTINEL_OS</h1>
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
                  Target Code Input
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 space-y-4">
                <div className="space-y-2">
                  <label className="text-xs text-primary/70 uppercase">Language Hint (Optional)</label>
                  <Input 
                    placeholder="e.g. typescript, python, go" 
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    className="rounded-none border-border bg-background focus-visible:ring-1 focus-visible:ring-primary font-mono text-sm"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs text-primary/70 uppercase">Source Code</label>
                  <Textarea 
                    placeholder="Paste raw logic here for deep inspection..."
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="min-h-[400px] rounded-none border-border bg-background focus-visible:ring-1 focus-visible:ring-primary font-mono text-sm resize-y"
                    spellCheck={false}
                  />
                </div>
                <Button 
                  onClick={handleAudit} 
                  disabled={createAuditMutation.isPending}
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
                      EXECUTE SECURITY AUDIT
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
                  <div className="text-sm text-primary/50 animate-pulse">Loading rulesets...</div>
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
                  <div className="text-xs text-primary/50">No rulesets loaded.</div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right Column - Results */}
          <div className="space-y-6">
            {!auditResult ? (
              <div className="h-full min-h-[500px] border border-dashed border-border flex flex-col items-center justify-center text-primary/30 p-8 text-center bg-card/20">
                <Shield className="w-16 h-16 mb-4 opacity-50" />
                <p className="text-sm tracking-widest uppercase">AWAITING TARGET PAYLOAD</p>
                <p className="text-xs mt-2 max-w-xs">System standing by to analyze code for logic flaws, vulnerabilities, and hardening opportunities.</p>
              </div>
            ) : (
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                
                {/* Result Summary */}
                <Card className="border-border bg-card rounded-none shadow-none">
                  <CardHeader className="border-b border-border pb-4 bg-secondary/20">
                    <div className="flex items-start justify-between">
                      <div>
                        <CardTitle className="text-lg font-bold uppercase tracking-widest">
                          Audit Report
                        </CardTitle>
                        <CardDescription className="text-primary/70 font-mono mt-1 text-xs">
                          {auditResult.summary}
                        </CardDescription>
                      </div>
                      <Badge variant="outline" className={`rounded-none border uppercase tracking-wider text-xs py-1 px-2 ${getSeverityColor(auditResult.severity)}`}>
                        {auditResult.severity} RISK
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="p-4 flex flex-col gap-4">
                    <div className="flex justify-between items-center bg-background border border-border p-4">
                      <div className="text-sm uppercase text-primary/70">Security Score</div>
                      <div className="text-2xl font-bold">{auditResult.score}/100</div>
                    </div>
                    
                    {(auditResult.hardened || auditResult.vulnerabilities.length === 0) ? (
                      <div className="flex items-center gap-3 bg-primary/10 border border-primary text-primary p-4">
                        <ShieldCheck className="w-6 h-6" />
                        <div>
                          <h4 className="font-bold uppercase tracking-wider">System Hardened</h4>
                          <p className="text-xs opacity-80">{auditResult.badge || "No critical vulnerabilities detected in this payload."}</p>
                        </div>
                      </div>
                    ) : null}
                  </CardContent>
                </Card>

                {/* Vulnerabilities */}
                {auditResult.vulnerabilities.length > 0 && (
                  <div className="space-y-4">
                    <h3 className="text-sm font-bold uppercase tracking-widest border-b border-border pb-2 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-red-500" />
                      Detected Anomalies ({auditResult.vulnerabilities.length})
                    </h3>
                    <div className="space-y-4">
                      {auditResult.vulnerabilities.map((vuln, idx) => (
                        <Card key={idx} className="border-border bg-card rounded-none shadow-none overflow-hidden">
                          <div className={`h-1 w-full ${getSeverityColor(vuln.severity).split(' ')[0].replace('text-', 'bg-')}`} />
                          <CardContent className="p-4 space-y-3">
                            <div className="flex items-start justify-between">
                              <div className="flex items-center gap-2">
                                <AlertTriangle className={`w-4 h-4 ${getSeverityColor(vuln.severity).split(' ')[0]}`} />
                                <span className="font-bold text-sm uppercase">{vuln.type}</span>
                              </div>
                              <Badge variant="outline" className={`rounded-none text-[10px] ${getSeverityColor(vuln.severity)}`}>
                                L:{vuln.line}
                              </Badge>
                            </div>
                            <div className="bg-background border border-border p-2 text-xs font-mono text-primary/80 overflow-x-auto">
                              <span className="text-primary/50 select-none mr-2">{String(vuln.line).padStart(3, ' ')} |</span>
                              {vuln.evidence}
                            </div>
                            <div className="text-xs text-primary/70 pl-2 border-l-2 border-primary/30">
                              <span className="font-bold text-primary mr-1">Remediation:</span>
                              {vuln.remediation}
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </div>
                )}

                {/* Secure Rewrite */}
                {auditResult.secureRewrite && (
                  <Card className="border-border bg-card rounded-none shadow-none mt-6">
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
                            <ShieldBan className="w-3 h-3" /> Vulnerable Origin
                          </div>
                          <pre className="text-xs overflow-x-auto text-primary/70">{auditResult.secureRewrite.vulnerable}</pre>
                        </div>
                        <div className="p-4 bg-primary/5">
                          <div className="text-[10px] text-primary uppercase tracking-widest mb-2 font-bold flex items-center gap-1">
                            <ShieldCheck className="w-3 h-3" /> Hardened Target
                          </div>
                          <pre className="text-xs overflow-x-auto text-primary font-bold">{auditResult.secureRewrite.hardened}</pre>
                        </div>
                      </div>
                      <div className="p-4 border-t border-border text-xs text-primary/70 bg-secondary/20">
                        <span className="font-bold text-primary mr-1">ANALYSIS NOTES:</span>
                        {auditResult.secureRewrite.notes}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Checklist */}
                {auditResult.checklist && auditResult.checklist.length > 0 && (
                  <Card className="border-border bg-card rounded-none shadow-none mt-6">
                    <CardHeader className="border-b border-border pb-3">
                      <CardTitle className="text-sm font-bold uppercase tracking-widest">
                        Security Checklist
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-4">
                      <ul className="space-y-2 text-xs">
                        {auditResult.checklist.map((item, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <CheckCircle className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                            <span className="text-primary/80">{item}</span>
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

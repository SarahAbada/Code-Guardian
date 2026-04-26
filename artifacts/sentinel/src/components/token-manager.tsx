import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  Key,
  KeyRound,
  Loader2,
  Plus,
  Copy,
  Check,
  Trash2,
  ShieldAlert,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

type TokenSummary = {
  id: number;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  requestCount: number;
  revoked: boolean;
};

type CreateTokenResponse = {
  id: number;
  name: string;
  prefix: string;
  createdAt: string;
  token: string;
  notice: string;
};

const tokensUrl = `${import.meta.env.BASE_URL}api/tokens`;
const tokenUrl = (id: number) => `${import.meta.env.BASE_URL}api/tokens/${id}`;

async function jsonFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { message?: string };
    throw new Error(body.message ?? `Request failed: ${res.status}`);
  }
  return (await res.json()) as T;
}

export function TokenManager() {
  const [tokens, setTokens] = useState<TokenSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [newToken, setNewToken] = useState<CreateTokenResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const refresh = async () => {
    setLoading(true);
    try {
      const data = await jsonFetch<{ tokens: TokenSummary[] }>(tokensUrl);
      setTokens(data.tokens);
    } catch (err) {
      toast({
        title: "Token fetch failed",
        description: (err as Error).message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const handleCreate = async () => {
    const trimmed = name.trim();
    if (!trimmed) {
      toast({
        title: "Project name required",
        description: "Give the token a project name (e.g. github-actions-ci).",
        variant: "destructive",
      });
      return;
    }
    setCreating(true);
    try {
      const created = await jsonFetch<CreateTokenResponse>(tokensUrl, {
        method: "POST",
        body: JSON.stringify({ name: trimmed }),
      });
      setNewToken(created);
      setName("");
      setCopied(false);
      await refresh();
    } catch (err) {
      toast({
        title: "Could not create token",
        description: (err as Error).message,
        variant: "destructive",
      });
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (id: number) => {
    try {
      await jsonFetch(tokenUrl(id), { method: "DELETE" });
      await refresh();
      toast({ title: "Token revoked", description: `Token #${id} revoked.` });
    } catch (err) {
      toast({
        title: "Revoke failed",
        description: (err as Error).message,
        variant: "destructive",
      });
    }
  };

  const handleCopy = async () => {
    if (!newToken) return;
    try {
      await navigator.clipboard.writeText(newToken.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast({
        title: "Copy failed",
        description: "Select and copy manually.",
        variant: "destructive",
      });
    }
  };

  return (
    <Card className="border-border bg-card rounded-none shadow-none">
      <CardHeader className="border-b border-border bg-secondary/30 rounded-none pb-3">
        <CardTitle className="text-sm font-bold uppercase tracking-widest text-primary flex items-center gap-2">
          <KeyRound className="w-4 h-4" />
          CLI / API Project Tokens
        </CardTitle>
        <CardDescription className="text-xs text-primary/60 font-mono mt-1">
          Provision per-project tokens for the Sentinel CLI. Tokens are stored
          as SHA-256 hashes; the raw value is shown once.
        </CardDescription>
      </CardHeader>
      <CardContent className="p-4 space-y-4">
        <div className="flex gap-2">
          <Input
            placeholder="Project name (e.g. github-actions-ci)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !creating) handleCreate();
            }}
            data-testid="input-token-name"
            className="rounded-none border-border bg-background focus-visible:ring-1 focus-visible:ring-primary font-mono text-xs"
          />
          <Button
            onClick={handleCreate}
            disabled={creating}
            data-testid="button-create-token"
            className="rounded-none border border-primary hover:bg-primary hover:text-primary-foreground uppercase tracking-widest text-xs"
            variant="ghost"
          >
            {creating ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Plus className="w-3 h-3 mr-1" /> Token
              </>
            )}
          </Button>
        </div>

        {newToken && (
          <div
            data-testid="card-new-token"
            className="border border-yellow-500/60 bg-yellow-500/5 p-3 space-y-2"
          >
            <div className="flex items-start gap-2 text-yellow-500">
              <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" />
              <div className="text-[11px] uppercase tracking-widest font-bold">
                Copy now &mdash; shown once
              </div>
            </div>
            <div className="text-xs text-primary/70">
              Project: <span className="text-primary font-bold">{newToken.name}</span>
            </div>
            <div className="flex items-stretch gap-1">
              <code className="flex-1 bg-background border border-border p-2 text-[11px] font-mono break-all text-primary">
                {newToken.token}
              </code>
              <Button
                onClick={handleCopy}
                variant="ghost"
                data-testid="button-copy-token"
                className="rounded-none border border-border px-2"
              >
                {copied ? (
                  <Check className="w-3 h-3 text-primary" />
                ) : (
                  <Copy className="w-3 h-3 text-primary" />
                )}
              </Button>
            </div>
            <div className="text-[10px] text-primary/50 italic">
              {newToken.notice}
            </div>
          </div>
        )}

        <div className="space-y-2">
          <div className="text-[10px] uppercase tracking-widest text-primary/60 border-b border-border pb-1 flex items-center justify-between">
            <span>Provisioned Tokens ({tokens.length})</span>
            {loading && <Loader2 className="w-3 h-3 animate-spin" />}
          </div>
          {tokens.length === 0 ? (
            <div className="text-xs text-primary/40 italic py-2">
              No tokens yet. Create one above to use the CLI endpoint.
            </div>
          ) : (
            <ul className="space-y-1.5">
              {tokens.map((t) => (
                <li
                  key={t.id}
                  data-testid={`token-row-${t.id}`}
                  className={`flex items-center justify-between gap-2 border border-border p-2 text-xs ${
                    t.revoked ? "opacity-50" : ""
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <Key className="w-3 h-3 text-primary/60 shrink-0" />
                      <span className="font-bold text-primary truncate">
                        {t.name}
                      </span>
                      {t.revoked && (
                        <span className="text-[10px] uppercase tracking-widest text-red-500 border border-red-500/40 px-1">
                          Revoked
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] text-primary/50 mt-0.5 font-mono">
                      {t.prefix}... &middot; {t.requestCount} requests
                      {t.lastUsedAt
                        ? ` · last used ${new Date(t.lastUsedAt).toLocaleString()}`
                        : " · never used"}
                    </div>
                  </div>
                  {!t.revoked && (
                    <Button
                      onClick={() => handleRevoke(t.id)}
                      variant="ghost"
                      data-testid={`button-revoke-${t.id}`}
                      className="rounded-none border border-red-500/40 hover:bg-red-500/10 hover:text-red-500 px-2 h-7"
                      title="Revoke token"
                    >
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

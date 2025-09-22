import React, { FormEvent, useEffect, useMemo, useState } from "react";

type MintResponse = {
  token: string;
  jti: string;
  exp: number;
  role: string;
  tenants: string | string[];
  bots: string | string[];
};

type RevokedInfo = {
  revoked_jtis: string[];
  stateless: boolean;
  revocation_backend: string;
};

type FormState = {
  role: string;
  tenants: string;
  bots: string;
  ttlHours: string;
};

function normalizeList(raw: string): string | string[] {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === "*") {
    return "*";
  }
  const parts = trimmed
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return parts.length === 0 ? "*" : parts;
}

function formatScope(value: string | string[]): string {
  if (value === "*") {
    return "*";
  }
  return Array.isArray(value) ? value.join(", ") : String(value);
}

function formatExp(exp: number): string {
  if (!exp) {
    return "";
  }
  try {
    const date = new Date(exp * 1000);
    return `${date.toLocaleString()} (${date.toISOString()})`;
  } catch (_err) {
    return String(exp);
  }
}

export default function AdminServiceTokensPanel() {
  const [form, setForm] = useState<FormState>({
    role: "viewer",
    tenants: "*",
    bots: "*",
    ttlHours: "720",
  });
  const [latest, setLatest] = useState<MintResponse | null>(null);
  const [revoked, setRevoked] = useState<RevokedInfo>({
    revoked_jtis: [],
    stateless: true,
    revocation_backend: "memory",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scopeSummary = useMemo(() => {
    if (!latest) {
      return "";
    }
    return `${formatScope(latest.tenants)} / ${formatScope(latest.bots)}`;
  }, [latest]);

  async function loadRevoked() {
    try {
      const resp = await fetch("/admin/api/tokens", { credentials: "include" });
      if (!resp.ok) {
        throw new Error(`Failed to load tokens (${resp.status})`);
      }
      const payload = (await resp.json()) as RevokedInfo;
      setRevoked({
        revoked_jtis: payload.revoked_jtis || [],
        stateless: Boolean(payload.stateless),
        revocation_backend: payload.revocation_backend || "memory",
      });
    } catch (err) {
      console.error("Failed to load revoked tokens", err);
      setError("Unable to load revoked token list");
    }
  }

  useEffect(() => {
    void loadRevoked();
  }, []);

  function parseTtl(raw: string): number | undefined {
    const trimmed = raw.trim();
    if (!trimmed) {
      return undefined;
    }
    const parsed = Number.parseInt(trimmed, 10);
    if (Number.isNaN(parsed) || parsed <= 0) {
      return undefined;
    }
    return parsed;
  }

  async function handleMint(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const tenants = normalizeList(form.tenants);
      const bots = normalizeList(form.bots);
      const body: Record<string, unknown> = {
        role: form.role,
        tenants,
        bots,
      };
      const ttl = parseTtl(form.ttlHours);
      if (ttl) {
        body.ttl_hours = ttl;
      }
      const resp = await fetch("/admin/api/tokens/mint", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        throw new Error(`Mint failed (${resp.status})`);
      }
      const payload = (await resp.json()) as MintResponse;
      setLatest(payload);
      await loadRevoked();
    } catch (err) {
      console.error("Mint token failed", err);
      setError("Unable to mint token; check server logs");
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke(jti: string) {
    if (!jti) {
      return;
    }
    if (!confirm(`Revoke token ${jti}?`)) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const resp = await fetch("/admin/api/tokens/revoke", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jti }),
      });
      if (!resp.ok) {
        throw new Error(`Revoke failed (${resp.status})`);
      }
      await loadRevoked();
    } catch (err) {
      console.error("Revoke token failed", err);
      setError("Unable to revoke token; check server logs");
    } finally {
      setBusy(false);
    }
  }

  async function copyToken() {
    if (!latest?.token) {
      return;
    }
    try {
      await navigator.clipboard.writeText(latest.token);
      alert("Token copied to clipboard");
    } catch (err) {
      console.error("Clipboard write failed", err);
      alert("Unable to copy token; copy manually");
    }
  }

  return (
    <div className="p-4 rounded-xl border flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold">Service Tokens</div>
        <button className="px-3 py-1 text-sm border rounded-lg" onClick={() => void loadRevoked()} disabled={busy}>
          Refresh
        </button>
      </div>
      <form className="flex flex-col gap-3" onSubmit={(event) => void handleMint(event)}>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex flex-col text-xs gap-1">
            Role
            <select
              className="border rounded-lg px-2 py-1"
              value={form.role}
              onChange={(event) => setForm((prev) => ({ ...prev, role: event.target.value }))}
            >
              <option value="viewer">viewer</option>
              <option value="operator">operator</option>
              <option value="admin">admin</option>
            </select>
          </label>
          <label className="flex flex-col text-xs gap-1">
            TTL (hours)
            <input
              className="border rounded-lg px-2 py-1"
              type="number"
              min={1}
              value={form.ttlHours}
              onChange={(event) => setForm((prev) => ({ ...prev, ttlHours: event.target.value }))}
            />
          </label>
          <label className="flex flex-col text-xs gap-1">
            Tenants (comma separated or "*")
            <input
              className="border rounded-lg px-2 py-1"
              value={form.tenants}
              onChange={(event) => setForm((prev) => ({ ...prev, tenants: event.target.value }))}
            />
          </label>
          <label className="flex flex-col text-xs gap-1">
            Bots (comma separated or "*")
            <input
              className="border rounded-lg px-2 py-1"
              value={form.bots}
              onChange={(event) => setForm((prev) => ({ ...prev, bots: event.target.value }))}
            />
          </label>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-1 border rounded-lg" type="submit" disabled={busy}>
            Mint Token
          </button>
          {error ? <span className="text-xs text-red-600">{error}</span> : null}
        </div>
      </form>
      {latest ? (
        <div className="flex flex-col gap-2 border rounded-lg p-3 bg-neutral-50">
          <div className="flex items-center justify-between text-xs">
            <span>
              <strong>JTI:</strong> {latest.jti}
            </span>
            <button className="px-3 py-1 border rounded" onClick={() => void copyToken()}>
              Copy token
            </button>
          </div>
          <div className="text-xs text-neutral-600">
            role: {latest.role} · scope: {scopeSummary} · exp: {formatExp(latest.exp)}
          </div>
          <textarea className="w-full text-xs border rounded-lg p-2" value={latest.token} readOnly rows={3} />
        </div>
      ) : null}
      <div className="flex flex-col gap-2">
        <div className="text-xs text-neutral-600">
          Revocation backend: {revoked.revocation_backend} · stateless tokens
        </div>
        {revoked.revoked_jtis.length === 0 ? (
          <div className="text-xs text-neutral-500">No revoked tokens recorded.</div>
        ) : (
          <table className="w-full text-xs border rounded-lg">
            <thead>
              <tr className="text-left bg-neutral-100">
                <th className="p-2">JTI</th>
                <th className="p-2 w-24">Actions</th>
              </tr>
            </thead>
            <tbody>
              {revoked.revoked_jtis.map((jti) => (
                <tr key={jti} className="border-t">
                  <td className="p-2 font-mono text-[11px]">{jti}</td>
                  <td className="p-2">
                    <button
                      className="px-2 py-1 border rounded"
                      disabled={busy}
                      onClick={() => void handleRevoke(jti)}
                    >
                      Revoke again
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

import React, { useEffect, useState } from "react";

export default function MitigationToggles({
  tenant,
  bot,
  csrfToken,
}: {
  tenant: string;
  bot: string;
  csrfToken?: string;
}) {
  const [mode, setMode] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  function csrf(): string {
    if (csrfToken) return csrfToken;
    const m = document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement | null;
    return m?.content || "";
  }

  async function load() {
    setLoading(true);
    try {
      const r = await fetch(
        `/admin/api/mitigation-mode?tenant=${encodeURIComponent(tenant)}&bot=${encodeURIComponent(bot)}`,
        { credentials: "include" }
      );
      const j = await r.json();
      setMode(j.mode || "clarify");
    } catch (err) {
      console.error("Failed to load mitigation mode", err);
    } finally {
      setLoading(false);
    }
  }

  async function save(next: string) {
    setSaving(true);
    try {
      const token = csrf();
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) {
        headers["X-CSRF-Token"] = token;
      }
      const r = await fetch(`/admin/api/mitigation-mode`, {
        method: "PUT",
        credentials: "include",
        headers,
        body: JSON.stringify({ tenant, bot, mode: next, csrf_token: token }),
      });
      if (!r.ok) {
        alert("Failed to save mode");
        return;
      }
      setMode(next);
    } catch (err) {
      console.error("Failed to save mitigation mode", err);
      alert("Failed to save mode");
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    void load();
  }, [tenant, bot]);

  const Choice = ({ value, label }: { value: string; label: string }) => (
    <button
      className={`px-3 py-1 rounded-lg border ${mode === value ? "font-semibold" : ""}`}
      onClick={() => save(value)}
      disabled={loading || saving}
    >
      {label}
    </button>
  );

  return (
    <div className="p-4 rounded-xl border flex flex-col gap-2">
      <div className="text-sm">
        Mitigation mode for <b>{tenant}</b>/<b>{bot}</b>
      </div>
      <div className="text-xs opacity-60">Values persist (file/redis).</div>
      <div className="flex gap-2">
        <Choice value="block" label="Block" />
        <Choice value="clarify" label="Clarify" />
        <Choice value="redact" label="Redact" />
      </div>
      {(loading || saving) && (
        <div className="text-xs opacity-60">{loading ? "Loading…" : "Saving…"}</div>
      )}
    </div>
  );
}


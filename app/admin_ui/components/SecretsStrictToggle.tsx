import React, { useEffect, useState } from "react";

type Props = {
  tenant: string;
  bot: string;
  csrfToken?: string;
};

export default function SecretsStrictToggle({ tenant, bot, csrfToken }: Props) {
  const [enabled, setEnabled] = useState<boolean>(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  function csrf(): string {
    if (csrfToken) return csrfToken;
    const meta = document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement | null;
    return meta?.content || "";
  }

  async function load() {
    setLoading(true);
    try {
      const resp = await fetch(
        `/admin/api/secrets/strict?tenant=${encodeURIComponent(tenant)}&bot=${encodeURIComponent(bot)}`,
        { credentials: "include" }
      );
      const body = await resp.json();
      setEnabled(Boolean(body?.enabled));
    } catch (err) {
      console.error("Failed to load strict secrets status", err);
    } finally {
      setLoading(false);
    }
  }

  async function save(next: boolean) {
    setSaving(true);
    try {
      const resp = await fetch(`/admin/api/secrets/strict`, {
        method: "PUT",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf(),
        },
        body: JSON.stringify({ tenant, bot, enabled: next, csrf_token: csrf() }),
      });
      if (!resp.ok) {
        alert("Failed to update secrets pack");
        return;
      }
      setEnabled(next);
    } catch (err) {
      console.error("Failed to save strict secrets status", err);
      alert("Failed to update secrets pack");
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    void load();
  }, [tenant, bot]);

  return (
    <div className="p-4 rounded-xl border flex items-center justify-between">
      <div>
        <div className="text-sm">
          <b>Stricter secrets pack</b> (generic tokens)
        </div>
        <div className="text-xs opacity-70">
          {enabled ? "Enabled" : "Disabled"} for {tenant}/{bot}
        </div>
      </div>
      <button
        className="px-3 py-1 rounded-lg border"
        disabled={loading || saving}
        onClick={() => save(!enabled)}
      >
        {saving ? "Saving…" : enabled ? "Disable" : "Enable"}
      </button>
    </div>
  );
}

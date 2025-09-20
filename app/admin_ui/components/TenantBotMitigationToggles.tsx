import React, { useEffect, useState } from "react";

type Mode = "block" | "clarify" | "redact";

export default function TenantBotMitigationToggles({
  tenant,
  bot,
  csrfToken,
}: { tenant: string; bot: string; csrfToken: string }) {
  const [mode, setMode] = useState<Mode>("clarify");
  const [source, setSource] = useState<"explicit" | "default">("default");
  const [saving, setSaving] = useState(false);

  async function fetchMode() {
    const r = await fetch(
      `/admin/api/mitigation/modes?tenant=${encodeURIComponent(tenant)}&bot=${encodeURIComponent(bot)}`,
      {
        credentials: "include",
      }
    );
    const j = await r.json();
    setMode(j.mode);
    setSource(j.source);
  }

  async function save() {
    setSaving(true);
    try {
      const r = await fetch(`/admin/api/mitigation/modes`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        credentials: "include",
        body: JSON.stringify({ tenant, bot, mode }),
      });
      const j = await r.json();
      setMode(j.mode);
      setSource(j.source);
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    fetchMode();
  }, [tenant, bot]);

  return (
    <div className="p-4 rounded-xl border">
      <div className="mb-2 text-sm opacity-70">
        Mitigation mode for <b>{tenant}</b> / <b>{bot}</b> ({source})
      </div>
      <div className="flex gap-4 items-center">
        {(["block", "clarify", "redact"] as Mode[]).map((m) => (
          <label key={m} className="flex items-center gap-1 cursor-pointer">
            <input
              type="radio"
              name="mitigation-mode"
              checked={mode === m}
              onChange={() => setMode(m)}
            />
            <span className="capitalize">{m}</span>
          </label>
        ))}
        <button
          className="px-3 py-1 rounded-lg border"
          disabled={saving}
          onClick={save}
        >
          {saving ? "Saving..." : "Save"}
        </button>
      </div>
    </div>
  );
}

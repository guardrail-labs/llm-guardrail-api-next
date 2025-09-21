import React, { useEffect, useState } from "react";

type Item = {
  ts_ms: number;
  action: string;
  actor_email?: string;
  actor_role?: string;
  tenant?: string;
  bot?: string;
  outcome: string;
  meta: Record<string, unknown>;
};

export default function AdminAuditPanel() {
  const [items, setItems] = useState<Item[]>([]);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    setBusy(true);
    try {
      const r = await fetch("/admin/api/audit/recent?limit=20", { credentials: "include" });
      if (!r.ok) {
        throw new Error(`HTTP ${r.status}`);
      }
      const j = (await r.json()) as Item[];
      setItems(j);
    } catch (err) {
      console.warn("Failed to load admin audit feed", err);
      setItems([]);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  function fmt(ts: number) {
    try {
      return new Date(ts).toLocaleString();
    } catch (err) {
      console.warn("Failed to format timestamp", err);
      return String(ts);
    }
  }

  return (
    <div className="p-4 rounded-xl border flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="text-sm">
          <b>Recent Admin Actions</b>
        </div>
        <div className="flex gap-2">
          <a
            className="px-3 py-1 rounded-lg border"
            href="/admin/api/audit/export.ndjson"
            download
          >
            Download NDJSON
          </a>
          <button className="px-3 py-1 rounded-lg border" onClick={refresh} disabled={busy}>
            {busy ? "…" : "Refresh"}
          </button>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        {items.map((it, idx) => (
          <div key={idx} className="text-xs border rounded-lg p-2">
            <div className="flex justify-between">
              <div>
                <b>{it.action}</b>
                <span className={`ml-2 ${it.outcome === "ok" ? "text-green-600" : "text-red-600"}`}>
                  {it.outcome}
                </span>
              </div>
              <div className="opacity-60">{fmt(it.ts_ms)}</div>
            </div>
            <div className="opacity-75">
              {it.actor_email || "-"} ({it.actor_role || "-"}) · {it.tenant || "-"} / {it.bot || "-"}
            </div>
          </div>
        ))}
        {items.length === 0 && <div className="text-xs opacity-60">No recent actions.</div>}
      </div>
    </div>
  );
}

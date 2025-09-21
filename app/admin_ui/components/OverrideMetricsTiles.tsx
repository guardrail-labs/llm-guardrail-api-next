import React, { useEffect, useState } from "react";

type Totals = { block: number; clarify: number; redact: number };

export default function OverrideMetricsTiles() {
  const [totals, setTotals] = useState<Totals>({ block: 0, clarify: 0, redact: 0 });
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    try {
      const r = await fetch("/admin/api/metrics/mitigation-overrides", { credentials: "include" });
      if (!r.ok) return;
      const j = await r.json();
      setTotals(j?.totals ?? { block: 0, clarify: 0, redact: 0 });
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    load();
    const id = setInterval(load, 10_000);
    return () => clearInterval(id);
  }, []);

  const Tile = ({ label, value }: { label: string; value: number }) => (
    <div className="p-4 rounded-xl border min-w-28">
      <div className="text-xs opacity-70">{label}</div>
      <div className="text-2xl font-semibold" data-test={`override-${label.toLowerCase()}`}>{value}</div>
    </div>
  );

  return (
    <div className="p-4 rounded-xl border flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="text-sm"><b>Mitigation Overrides</b></div>
        <button className="px-3 py-1 rounded-lg border" onClick={load} disabled={busy}>
          {busy ? "…" : "Refresh"}
        </button>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <Tile label="Block" value={totals.block ?? 0} />
        <Tile label="Clarify" value={totals.clarify ?? 0} />
        <Tile label="Redact" value={totals.redact ?? 0} />
      </div>
    </div>
  );
}

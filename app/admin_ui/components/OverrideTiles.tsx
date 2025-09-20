import React, { useEffect, useState } from "react";

type Totals = { block: number; clarify: number; redact: number };

type OverridesResp = { totals: Totals; since_ms: number };

export default function OverrideTiles() {
  const [totals, setTotals] = useState<Totals>({ block: 0, clarify: 0, redact: 0 });
  const [since, setSince] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function fetchTotals() {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/admin/api/metrics/mitigation-overrides", {
        credentials: "include",
      });
      if (!r.ok) {
        throw new Error(`HTTP ${r.status}`);
      }
      const j: OverridesResp = await r.json();
      setTotals(j.totals ?? { block: 0, clarify: 0, redact: 0 });
      setSince(typeof j.since_ms === "number" ? j.since_ms : null);
    } catch (err) {
      console.error("Failed to fetch mitigation override totals", err);
      setError("Refresh failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void fetchTotals();
  }, []);

  const Tile = ({ label, value }: { label: string; value: number }) => (
    <div className="p-4 rounded-xl border min-w-[140px]">
      <div className="text-xs opacity-60">{label}</div>
      <div className="text-2xl font-semibold">{value}</div>
    </div>
  );

  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-3">
        <Tile label="Overrides: Block" value={totals.block} />
        <Tile label="Overrides: Clarify" value={totals.clarify} />
        <Tile label="Overrides: Redact" value={totals.redact} />
      </div>
      <div className="flex items-center gap-2">
        <button className="px-3 py-1 rounded-lg border" onClick={fetchTotals} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
        {error && <span className="text-xs text-red-500">{error}</span>}
        {since && (
          <span className="text-xs opacity-60">
            Counting since: {new Date(since).toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}

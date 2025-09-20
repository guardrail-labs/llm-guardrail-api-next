import React, { useEffect, useMemo, useState } from "react";

type Totals = { block: number; clarify: number; redact: number };

type Snapshot = {
  totals: Totals;
  since_ms: number;
};

function diffLabel(current: number, previous: number | undefined) {
  if (previous === undefined) {
    return "";
  }
  const delta = current - previous;
  if (delta === 0) {
    return "";
  }
  const direction = delta > 0 ? "+" : "";
  return `${direction}${delta}`;
}

export default function OverrideTiles() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [previous, setPrevious] = useState<Totals | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const totals = snapshot?.totals ?? { block: 0, clarify: 0, redact: 0 };

  const deltas = useMemo(
    () => ({
      block: diffLabel(totals.block, previous?.block),
      clarify: diffLabel(totals.clarify, previous?.clarify),
      redact: diffLabel(totals.redact, previous?.redact),
    }),
    [totals, previous]
  );

  async function fetchTotals() {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/admin/api/metrics/mitigation-overrides", {
        credentials: "include",
      });
      if (!r.ok) {
        throw new Error(`Request failed (${r.status})`);
      }
      const j: Snapshot = await r.json();
      setPrevious(snapshot?.totals ?? null);
      setSnapshot(j);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch totals");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchTotals();
    const interval = setInterval(fetchTotals, 30_000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const Tile = ({ label, value, delta }: { label: string; value: number; delta: string }) => (
    <div className="p-4 rounded-xl border min-w-[140px]">
      <div className="text-xs opacity-60">{label}</div>
      <div className="text-2xl font-semibold">{value}</div>
      {delta && <div className="text-xs text-green-600">{delta}</div>}
    </div>
  );

  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-3 flex-wrap">
        <Tile label="Overrides: Block" value={totals.block} delta={deltas.block} />
        <Tile label="Overrides: Clarify" value={totals.clarify} delta={deltas.clarify} />
        <Tile label="Overrides: Redact" value={totals.redact} delta={deltas.redact} />
      </div>
      <div className="flex items-center gap-2 flex-wrap text-sm">
        <button className="px-3 py-1 rounded-lg border" onClick={fetchTotals} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
        {snapshot?.since_ms && (
          <span className="text-xs opacity-60">
            Counting since process start: {new Date(snapshot.since_ms).toLocaleString()}
          </span>
        )}
        {error && <span className="text-xs text-red-600">{error}</span>}
      </div>
    </div>
  );
}

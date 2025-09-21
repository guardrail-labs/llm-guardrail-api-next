import React, { useCallback, useEffect, useState } from "react";

import { Pager } from "@/admin_ui/components/Pager";

type Outcome = "allow" | "block" | "clarify" | "redact" | "";

type Filters = {
  tenant?: string;
  bot?: string;
  sinceMs?: number | null;
  outcome?: Outcome;
  ruleId?: string;
  requestId?: string;
};

type AdjudicationRecord = {
  request_id: string;
  tenant?: string;
  bot?: string;
  decision?: string;
  ts?: string;
};

export default function AdjudicationsPage(): JSX.Element {
  const [filters, setFilters] = useState<Filters>({});
  const [limit] = useState<number>(50);
  const [items, setItems] = useState<AdjudicationRecord[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [prevCursor, setPrevCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  const fetchPage = useCallback(
    async (options?: { dir?: "next" | "prev"; cursor?: string }) => {
      const dir = options?.dir ?? "next";
      const cursor = options?.cursor;
      const params = new URLSearchParams({ limit: String(limit), dir });
      if (cursor) params.set("cursor", cursor);
      if (filters.tenant) params.set("tenant", filters.tenant);
      if (filters.bot) params.set("bot", filters.bot);
      if (typeof filters.sinceMs === "number") params.set("since", String(filters.sinceMs));
      if (filters.outcome) params.set("outcome", filters.outcome);
      if (filters.ruleId) params.set("rule_id", filters.ruleId);
      if (filters.requestId) params.set("request_id", filters.requestId);

      setLoading(true);
      try {
        const res = await fetch(`/admin/api/adjudications?${params.toString()}`, {
          credentials: "include",
        });
        if (!res.ok) {
          throw new Error(`Failed to load adjudications (${res.status})`);
        }
        const payload = await res.json();
        setItems(Array.isArray(payload.items) ? payload.items : []);
        setNextCursor(payload.next_cursor ?? null);
        setPrevCursor(payload.prev_cursor ?? null);
      } finally {
        setLoading(false);
      }
    },
    [filters, limit],
  );

  useEffect(() => {
    void fetchPage({ dir: "next" });
  }, [fetchPage]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Adjudications</h1>
        <Pager
          nextCursor={nextCursor}
          prevCursor={prevCursor}
          onPage={(dir, cursor) => {
            void fetchPage({ dir, cursor });
          }}
        />
      </div>
      {loading ? (
        <div>Loading…</div>
      ) : (
        <ul className="space-y-2">
          {items.map((item) => (
            <li key={item.request_id ?? Math.random()} className="rounded border p-3">
              <div className="text-sm font-mono">{item.request_id}</div>
              <div className="text-xs text-gray-500">
                {item.tenant} · {item.bot} · {item.decision}
              </div>
            </li>
          ))}
        </ul>
      )}
      <button
        className="self-start rounded border px-3 py-1"
        onClick={() => {
          setFilters((prev) => ({ ...prev }));
          void fetchPage({ dir: "next" });
        }}
      >
        Refresh
      </button>
    </div>
  );
}

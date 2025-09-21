import React, { useEffect, useState } from "react";

type Stats = {
  size: number;
  oldest_ts_ms?: number | null;
  newest_ts_ms?: number | null;
  last_error?: string | null;
};

type Props = {
  csrfToken?: string;
};

function formatTimestamp(ts?: number | null): string {
  if (!ts) {
    return "";
  }
  const date = new Date(ts);
  return date.toLocaleString();
}

export default function WebhookDLQPanel({ csrfToken }: Props) {
  const [stats, setStats] = useState<Stats>({ size: 0 });
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try {
      const response = await fetch("/admin/api/webhooks/dlq", { credentials: "include" });
      if (!response.ok) {
        throw new Error(`Failed to load DLQ stats (${response.status})`);
      }
      const payload = (await response.json()) as Stats;
      setStats(payload);
    } catch (err) {
      console.error("Failed to refresh DLQ stats", err);
      alert("Unable to load DLQ stats. Check server logs.");
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  function csrf(): string {
    if (csrfToken) {
      return csrfToken;
    }
    const meta = document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement | null;
    return meta?.content || "";
  }

  async function post(path: string) {
    setBusy(true);
    try {
      const response = await fetch(path, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csrf_token: csrf() }),
      });
      if (!response.ok) {
        alert("Operation failed; check server logs for details.");
      }
      await refresh();
    } catch (err) {
      console.error("DLQ action failed", err);
      alert("Operation failed; check server logs for details.");
    } finally {
      setBusy(false);
    }
  }

  const hasItems = stats.size > 0;

  return (
    <div className="p-4 rounded-xl border flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between">
          <div className="text-sm">
            <b>Webhook DLQ</b> — size: {stats.size}
            {stats.last_error ? <span className="ml-2 opacity-70">last error: {stats.last_error}</span> : null}
          </div>
          <button className="px-3 py-1 rounded-lg border" onClick={() => void refresh()} disabled={busy}>
            Refresh
          </button>
        </div>
        {stats.oldest_ts_ms ? (
          <div className="text-xs text-neutral-500">
            oldest: {formatTimestamp(stats.oldest_ts_ms)}
            {stats.newest_ts_ms ? ` · newest: ${formatTimestamp(stats.newest_ts_ms)}` : null}
          </div>
        ) : null}
      </div>
      <div className="flex gap-2">
        <button
          className="px-3 py-1 rounded-lg border"
          disabled={busy || !hasItems}
          onClick={() => {
            if (confirm("Retry all DLQ items?")) {
              void post("/admin/api/webhooks/dlq/retry");
            }
          }}
        >
          Retry DLQ
        </button>
        <button
          className="px-3 py-1 rounded-lg border"
          disabled={busy || !hasItems}
          onClick={() => {
            if (confirm("Purge ALL DLQ items? This cannot be undone.")) {
              void post("/admin/api/webhooks/dlq/purge");
            }
          }}
        >
          Purge DLQ
        </button>
      </div>
    </div>
  );
}

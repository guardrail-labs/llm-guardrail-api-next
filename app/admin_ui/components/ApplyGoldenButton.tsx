import React, { useEffect, useState } from "react";

type FeaturesResp = { golden_one_click?: boolean };

export default function ApplyGoldenButton() {
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function loadFeatures() {
      try {
        const r = await fetch("/admin/api/features", { credentials: "include" });
        if (!r.ok) {
          throw new Error(`HTTP ${r.status}`);
        }
        const j: FeaturesResp = await r.json();
        if (!cancelled) {
          setEnabled(Boolean(j.golden_one_click));
        }
      } catch (err) {
        console.warn("Failed to load admin features", err);
        if (!cancelled) {
          setEnabled(false);
        }
      }
    }
    void loadFeatures();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!enabled) {
    return null;
  }

  async function apply() {
    if (!window.confirm("Apply Golden Packs now? This will refresh caches.")) {
      return;
    }
    setBusy(true);
    try {
      const r = await fetch("/admin/bindings/apply_golden", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant: "demo", bot: "site" }),
      });
      if (r.ok) {
        window.alert("Applied successfully.");
      } else {
        window.alert("Apply failed; check logs.");
      }
    } catch (err) {
      console.error("Failed to apply golden packs", err);
      window.alert("Apply failed; check logs.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <button className="px-3 py-1 rounded-lg border" onClick={apply} disabled={busy}>
      {busy ? "Applying…" : "Apply Golden Packs"}
    </button>
  );
}


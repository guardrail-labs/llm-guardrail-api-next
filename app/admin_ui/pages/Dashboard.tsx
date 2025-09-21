import React from "react";

import ApplyGoldenButton from "@/admin_ui/components/ApplyGoldenButton";
import MitigationToggles from "@/admin_ui/components/MitigationToggles";
import OverrideTiles from "@/admin_ui/components/OverrideTiles";
import SecretsStrictToggle from "@/admin_ui/components/SecretsStrictToggle";
import WebhookDLQPanel from "@/admin_ui/components/WebhookDLQPanel";

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex gap-3">
        <ApplyGoldenButton />
      </div>
      <OverrideTiles />
      <MitigationToggles tenant="demo" bot="site" />
      <SecretsStrictToggle tenant="demo" bot="site" />
      <WebhookDLQPanel />
    </div>
  );
}

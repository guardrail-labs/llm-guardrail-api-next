import React from "react";

import AdminAuditPanel from "@/admin_ui/components/AdminAuditPanel";
import ApplyGoldenButton from "@/admin_ui/components/ApplyGoldenButton";
import MitigationToggles from "@/admin_ui/components/MitigationToggles";
import OverrideMetricsTiles from "@/admin_ui/components/OverrideMetricsTiles";
import SecretsStrictToggle from "@/admin_ui/components/SecretsStrictToggle";
import WebhookDLQPanel from "@/admin_ui/components/WebhookDLQPanel";
import AdminServiceTokensPanel from "@/admin_ui/components/AdminServiceTokensPanel";

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex gap-3">
        <ApplyGoldenButton />
      </div>
      <OverrideMetricsTiles />
      <MitigationToggles tenant="demo" bot="site" />
      <SecretsStrictToggle tenant="demo" bot="site" />
      <WebhookDLQPanel />
      <AdminServiceTokensPanel />
      <AdminAuditPanel />
    </div>
  );
}

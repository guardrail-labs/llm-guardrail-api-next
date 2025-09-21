import React from "react";

import ApplyGoldenButton from "@/admin_ui/components/ApplyGoldenButton";
import OverrideTiles from "@/admin_ui/components/OverrideTiles";

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex gap-3">
        <ApplyGoldenButton />
      </div>
      <OverrideTiles />
    </div>
  );
}

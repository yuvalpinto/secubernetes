import { motion } from "framer-motion";
import { RefreshCw, Shield } from "lucide-react";

import { Button } from "@/components/ui/button";

type DashboardHeaderProps = {
  lastUpdated: Date | null;
  onRefresh: () => void;
};

export function DashboardHeader({ lastUpdated, onRefresh }: DashboardHeaderProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="mb-8 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"
    >
      <div>
        <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-sm text-slate-600 shadow-sm">
          <Shield className="h-4 w-4" />
          Secubernetes Runtime Security Dashboard
        </div>
        <h1 className="mt-4 text-4xl font-semibold tracking-tight text-slate-950">
          Cluster Runtime Detection Overview
        </h1>
        <p className="mt-2 max-w-3xl text-slate-600">
          Live visibility into alerts, attack chains, and per-pod risk scoring collected from execve, openat,
          connect, threshold, LOF, and sequence analysis.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm text-slate-600 shadow-sm">
          Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "-"}
        </div>
        <Button onClick={onRefresh} className="rounded-2xl">
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>
    </motion.div>
  );
}

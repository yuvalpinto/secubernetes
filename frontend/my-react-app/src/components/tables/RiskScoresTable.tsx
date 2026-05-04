import { motion } from "framer-motion";

import { EmptyState } from "@/components/common/EmptyState";
import { LoadingState } from "@/components/common/LoadingState";
import { RiskBadge } from "@/components/common/RiskBadge";
import { Badge } from "@/components/ui/badge";
import type { ContainerRisk } from "@/types/risk";
import { formatMaxAlert, formatTs, truncateMiddle } from "@/utils/format";

type RiskScoresTableProps = {
  loading: boolean;
  riskItems: ContainerRisk[];
};

function RiskRow({ item }: { item: ContainerRisk }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 space-y-3 w-full">
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge level={item.final_risk_level} />
            <Badge variant="outline" className="rounded-full">
              score:{item.final_risk_score ?? "-"}
            </Badge>
            {item.pod_name ? (
              <Badge variant="outline" className="rounded-full">
                pod:{item.pod_name}
              </Badge>
            ) : null}
            {item.namespace ? (
              <Badge variant="outline" className="rounded-full">
                ns:{item.namespace}
              </Badge>
            ) : null}
          </div>

          <div className="grid gap-2 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-4">
            <div><span className="font-medium text-slate-900">Time:</span> {formatTs(item.ts)}</div>
            <div><span className="font-medium text-slate-900">Window Start:</span> {formatTs(item.window_start)}</div>
            <div><span className="font-medium text-slate-900">Window End:</span> {formatTs(item.window_end)}</div>
            <div><span className="font-medium text-slate-900">Container ID:</span> {truncateMiddle(item.container_id, 12, 6)}</div>

            <div><span className="font-medium text-slate-900">Sequence Score:</span> {item.sequence_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">Stat Score:</span> {item.stat_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">LOF Score:</span> {item.lof_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">Alerts Count:</span> {item.alerts_count ?? 0}</div>

            <div><span className="font-medium text-slate-900">Max Alert:</span> {formatMaxAlert(item.max_alert)}</div>
            <div><span className="font-medium text-slate-900">Threshold Anomaly:</span> {String(!!item.threshold_anomaly_detected)}</div>
            <div><span className="font-medium text-slate-900">Threshold Z:</span> {item.threshold_max_z_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">LOF Value:</span> {item.lof_value ?? 0}</div>

            <div><span className="font-medium text-slate-900">Exec Count:</span> {item.exec_count_window ?? 0}</div>
            <div><span className="font-medium text-slate-900">Sensitive Opens:</span> {item.sensitive_open_count_window ?? 0}</div>
            <div><span className="font-medium text-slate-900">Connect Count:</span> {item.connect_count_window ?? 0}</div>
            <div><span className="font-medium text-slate-900">Unique Dests:</span> {item.unique_destination_count_window ?? 0}</div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export function RiskScoresTable({ riskItems, loading }: RiskScoresTableProps) {
  if (loading) return <LoadingState message="Loading risk scores..." />;
  if (riskItems.length === 0) return <EmptyState message="No risk scores available yet." />;

  return (
    <div className="space-y-3">
      {riskItems.map((item) => (
        <RiskRow key={item._id || `${item.namespace}-${item.pod_name}-${item.ts}`} item={item} />
      ))}
    </div>
  );
}

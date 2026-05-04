import { motion } from "framer-motion";

import { EmptyState } from "@/components/common/EmptyState";
import { LoadingState } from "@/components/common/LoadingState";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import type { AlertDetails, KubernetesSourceEvent, SecurityAlert } from "@/types/alerts";
import { buildAttackSummary } from "@/utils/alerts";
import { formatDurationSeconds, formatTs, truncateMiddle } from "@/utils/format";

type RecentAlertsTableProps = {
  alerts: SecurityAlert[];
  loading: boolean;
};

function getAlertKey(alert: SecurityAlert) {
  if (typeof alert._id === "string") return alert._id;
  if (alert._id?.$oid) return alert._id.$oid;
  return `${alert.alert_type}-${alert.ts}`;
}

function KubernetesContext({ source }: { source: KubernetesSourceEvent }) {
  return (
    <div className="rounded-2xl bg-slate-50 p-3">
      <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
        Kubernetes Context
      </div>
      <div className="grid gap-2 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-3">
        <div><span className="font-medium text-slate-900">Pod:</span> {source?.pod_name || "-"}</div>
        <div><span className="font-medium text-slate-900">Namespace:</span> {source?.namespace || "-"}</div>
        <div><span className="font-medium text-slate-900">Container:</span> {source?.container_name || "-"}</div>
        <div><span className="font-medium text-slate-900">Runtime:</span> {source?.runtime || "-"}</div>
        <div><span className="font-medium text-slate-900">Resolver:</span> {source?.resolver_status || "-"}</div>
        <div><span className="font-medium text-slate-900">Pod UID:</span> {truncateMiddle(source?.pod_uid, 8, 6)}</div>
        <div className="md:col-span-2 xl:col-span-3">
          <span className="font-medium text-slate-900">Container ID:</span> {truncateMiddle(source?.container_id, 16, 8)}
        </div>
      </div>
    </div>
  );
}

function TriggeringDetails({ details }: { details: AlertDetails }) {
  if (!details.triggering_open && !details.triggering_exec) return null;

  return (
    <div className="grid gap-3 rounded-2xl bg-slate-50 p-3 md:grid-cols-2">
      {details.triggering_exec ? (
        <div>
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Triggering Exec</div>
          <div className="text-sm text-slate-700">{details.triggering_exec.filename || "-"}</div>
          <div className="text-xs text-slate-500">comm: {details.triggering_exec.comm || "-"}</div>
          <div className="text-xs text-slate-500">pid: {details.triggering_exec.pid ?? "-"}</div>
          <div className="text-xs text-slate-500">
            container: {truncateMiddle(details.triggering_exec.container_id, 12, 6)}
          </div>
        </div>
      ) : null}

      {details.triggering_open ? (
        <div>
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Triggering Open</div>
          <div className="text-sm text-slate-700">{details.triggering_open.filename || "-"}</div>
          <div className="text-xs text-slate-500">comm: {details.triggering_open.comm || "-"}</div>
          <div className="text-xs text-slate-500">rule: {details.triggering_open.matched_rule || "-"}</div>
          <div className="text-xs text-slate-500">pid: {details.triggering_open.pid ?? "-"}</div>
          <div className="text-xs text-slate-500">
            container: {truncateMiddle(details.triggering_open.container_id, 12, 6)}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function AlertRow({ alert }: { alert: SecurityAlert }) {
  const details = alert.details || {};
  const source = alert.source_event || {};
  const destination =
    details.destination ||
    (details.destination_ip && details.destination_port
      ? `${details.destination_ip}:${details.destination_port}`
      : null);

  const attackSummary = buildAttackSummary(alert);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <Badge variant="outline" className="rounded-full">{alert.alert_type || "unknown_alert"}</Badge>
            <Badge variant="outline" className="rounded-full">{alert.event_type || "unknown_event"}</Badge>
            {source.pod_name ? (
              <Badge variant="outline" className="rounded-full">
                pod:{source.pod_name}
              </Badge>
            ) : null}
            {source.namespace ? (
              <Badge variant="outline" className="rounded-full">
                ns:{source.namespace}
              </Badge>
            ) : null}
          </div>

          {attackSummary !== "-" ? (
            <div className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
              <span className="font-medium text-slate-900">Attack Chain:</span> {attackSummary}
            </div>
          ) : null}

          <div className="grid gap-2 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-4">
            <div><span className="font-medium text-slate-900">Process:</span> {source.comm || "-"}</div>
            <div><span className="font-medium text-slate-900">PID:</span> {source.pid ?? "-"}</div>
            <div><span className="font-medium text-slate-900">Lineage:</span> {alert.lineage_summary || "-"}</div>
            <div><span className="font-medium text-slate-900">Time:</span> {formatTs(alert.ts)}</div>

            {source.filename ? (
              <div className="md:col-span-2 xl:col-span-4">
                <span className="font-medium text-slate-900">Filename:</span> {source.filename}
              </div>
            ) : null}

            {destination ? (
              <div><span className="font-medium text-slate-900">Destination:</span> {destination}</div>
            ) : null}

            {typeof source.success === "boolean" ? (
              <div><span className="font-medium text-slate-900">Connect Success:</span> {String(source.success)}</div>
            ) : null}

            {source.ret !== undefined && source.ret !== null ? (
              <div><span className="font-medium text-slate-900">Connect Ret:</span> {source.ret}</div>
            ) : null}

            {details.correlation_window_seconds !== undefined ? (
              <div><span className="font-medium text-slate-900">Correlation Window:</span> {details.correlation_window_seconds}s</div>
            ) : null}

            {details.time_since_exec_seconds !== undefined ? (
              <div><span className="font-medium text-slate-900">Since Exec:</span> {formatDurationSeconds(details.time_since_exec_seconds)}</div>
            ) : null}

            {details.time_since_sensitive_open_seconds !== undefined ? (
              <div><span className="font-medium text-slate-900">Since Sensitive Open:</span> {formatDurationSeconds(details.time_since_sensitive_open_seconds)}</div>
            ) : null}
          </div>

          <KubernetesContext source={source} />
          <TriggeringDetails details={details} />
        </div>
      </div>
    </motion.div>
  );
}

export function RecentAlertsTable({ alerts, loading }: RecentAlertsTableProps) {
  if (loading) return <LoadingState message="Loading alerts..." />;
  if (alerts.length === 0) return <EmptyState message="No alerts match the current filter." />;

  return (
    <div className="space-y-3">
      {alerts.map((alert) => (
        <AlertRow key={getAlertKey(alert)} alert={alert} />
      ))}
    </div>
  );
}

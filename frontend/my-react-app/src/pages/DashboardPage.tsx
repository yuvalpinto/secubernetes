import { useMemo } from "react";
import {
  AlertTriangle,
  BarChart3,
  Boxes,
  Bug,
  Filter,
  Network,
  Radar,
  Search,
  Server,
  Shield,
} from "lucide-react";

import { alertEndpointOptions } from "@/api/alertsApi";
import { riskEndpointOptions } from "@/api/riskApi";
import { ErrorState } from "@/components/common/ErrorState";
import { RiskBadge } from "@/components/common/RiskBadge";
import { SectionCard } from "@/components/common/SectionCard";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { StatCard } from "@/components/common/StatCard";
import { DashboardHeader } from "@/components/layout/DashboardHeader";
import { RecentAlertsTable } from "@/components/tables/RecentAlertsTable";
import { RiskScoresTable } from "@/components/tables/RiskScoresTable";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type {
  AlertEndpointValue,
  AlertListResponse,
  AlertSummary,
  SecurityAlert,
} from "@/types/alerts";
import type { ContainerRisk, RiskEndpointValue, RiskListResponse } from "@/types/risk";
import { buildAttackSummary } from "@/utils/alerts";
import { formatMaxAlert, formatTs } from "@/utils/format";

type DashboardPageProps = {
  alertsPayload: AlertListResponse;
  endpoint: AlertEndpointValue;
  error: string;
  lastUpdated: Date | null;
  loadingAlerts: boolean;
  loadingRisk: boolean;
  loadingSummary: boolean;
  onEndpointChange: (value: AlertEndpointValue) => void;
  onRefresh: () => void;
  onRiskEndpointChange: (value: RiskEndpointValue) => void;
  onRiskPodNameChange: (value: string) => void;
  onSearchChange: (value: string) => void;
  riskEndpoint: RiskEndpointValue;
  riskPayload: RiskListResponse;
  riskPodName: string;
  search: string;
  summary: AlertSummary | null;
};

function includesSearch(value: unknown, query: string) {
  return JSON.stringify(value).toLowerCase().includes(query);
}

export function DashboardPage({
  alertsPayload,
  endpoint,
  error,
  lastUpdated,
  loadingAlerts,
  loadingRisk,
  loadingSummary,
  onEndpointChange,
  onRefresh,
  onRiskEndpointChange,
  onRiskPodNameChange,
  onSearchChange,
  riskEndpoint,
  riskPayload,
  riskPodName,
  search,
  summary,
}: DashboardPageProps) {
  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();
    const items = alertsPayload.items || [];
    if (!q) return items;
    return items.filter((alert) => includesSearch(alert, q));
  }, [alertsPayload, search]);

  const filteredRisk = useMemo(() => {
    const q = search.trim().toLowerCase();
    const items = riskPayload.items || [];
    if (!q) return items;
    return items.filter((item) => includesSearch(item, q));
  }, [riskPayload, search]);

  const severityMap = summary?.by_severity || {};
  const topTypes = summary?.top_alert_types || [];
  const latestChain = summary?.latest_chain || null;

  const highestRisk = useMemo<ContainerRisk | null>(() => {
    const items = riskPayload.items || [];
    if (!items.length) return null;
    return [...items].sort((a, b) => (b.final_risk_score || 0) - (a.final_risk_score || 0))[0];
  }, [riskPayload]);

  const criticalRiskCount = useMemo(() => {
    return (riskPayload.items || []).filter((item) => item.final_risk_level === "critical").length;
  }, [riskPayload]);

  const highRiskCount = useMemo(() => {
    return (riskPayload.items || []).filter((item) => item.final_risk_level === "high").length;
  }, [riskPayload]);

  return (
    <>
      <DashboardHeader lastUpdated={lastUpdated} onRefresh={onRefresh} />

      <ErrorState message={error} />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <StatCard title="Total Alerts" value={loadingSummary ? "..." : summary?.total_alerts ?? 0} icon={AlertTriangle} />
        <StatCard title="Critical Alerts" value={loadingSummary ? "..." : severityMap.critical ?? 0} icon={Bug} />
        <StatCard title="High Alerts" value={loadingSummary ? "..." : severityMap.high ?? 0} icon={Shield} />
        <StatCard title="Critical Risk Rows" value={loadingRisk ? "..." : criticalRiskCount} icon={Radar} />
        <StatCard title="High Risk Rows" value={loadingRisk ? "..." : highRiskCount} icon={BarChart3} />
      </div>

      <div className="mt-8 grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <SectionCard title="Container Risk Feed" icon={Radar} contentClassName="space-y-4">
          <div className="grid gap-3 lg:grid-cols-[1fr_220px_220px_auto]">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <Input
                value={search}
                onChange={(event) => onSearchChange(event.target.value)}
                placeholder="Search pod, namespace, risk, detector values, alert type..."
                className="rounded-2xl pl-9"
              />
            </div>

            <Select value={riskEndpoint} onValueChange={(value) => onRiskEndpointChange(value as RiskEndpointValue)}>
              <SelectTrigger className="rounded-2xl">
                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4" />
                  <SelectValue placeholder="Choose risk feed" />
                </div>
              </SelectTrigger>
              <SelectContent>
                {riskEndpointOptions.map((item) => (
                  <SelectItem key={item.value} value={item.value}>
                    {item.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Input
              value={riskPodName}
              onChange={(event) => onRiskPodNameChange(event.target.value)}
              placeholder="Pod name"
              className="rounded-2xl"
              disabled={riskEndpoint !== "by-pod"}
            />

            <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-2 text-sm text-slate-600">
              Showing {filteredRisk.length} / {riskPayload.count ?? 0}
            </div>
          </div>

          <RiskScoresTable riskItems={filteredRisk} loading={loadingRisk} />
        </SectionCard>

        <div className="space-y-6">
          <SectionCard title="Highest Current Risk" icon={Server}>
            {!highestRisk ? (
              <div className="text-sm text-slate-500">No risk scores yet.</div>
            ) : (
              <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <RiskBadge level={highestRisk.final_risk_level} />
                  <Badge variant="outline" className="rounded-full">
                    score:{highestRisk.final_risk_score}
                  </Badge>
                </div>

                <div className="text-sm text-slate-700 space-y-1">
                  <div><span className="font-medium text-slate-900">Pod:</span> {highestRisk.pod_name || "-"}</div>
                  <div><span className="font-medium text-slate-900">Namespace:</span> {highestRisk.namespace || "-"}</div>
                  <div><span className="font-medium text-slate-900">Sequence Score:</span> {highestRisk.sequence_score ?? 0}</div>
                  <div><span className="font-medium text-slate-900">Stat Score:</span> {highestRisk.stat_score ?? 0}</div>
                  <div><span className="font-medium text-slate-900">LOF Score:</span> {highestRisk.lof_score ?? 0}</div>
                  <div><span className="font-medium text-slate-900">Alerts Count:</span> {highestRisk.alerts_count ?? 0}</div>
                  <div><span className="font-medium text-slate-900">Max Alert:</span> {formatMaxAlert(highestRisk.max_alert)}</div>
                  <div><span className="font-medium text-slate-900">Time:</span> {formatTs(highestRisk.ts)}</div>
                </div>
              </div>
            )}
          </SectionCard>

          <SectionCard title="Alert Feed" icon={Network} contentClassName="space-y-4">
            <div className="grid gap-3 lg:grid-cols-[1fr_220px_auto]">
              <div />
              <Select value={endpoint} onValueChange={(value) => onEndpointChange(value as AlertEndpointValue)}>
                <SelectTrigger className="rounded-2xl">
                  <div className="flex items-center gap-2">
                    <Filter className="h-4 w-4" />
                    <SelectValue placeholder="Choose feed" />
                  </div>
                </SelectTrigger>
                <SelectContent>
                  {alertEndpointOptions.map((item) => (
                    <SelectItem key={item.value} value={item.value}>
                      {item.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-2 text-sm text-slate-600">
                Showing {filteredAlerts.length} / {alertsPayload.count ?? 0}
              </div>
            </div>

            <RecentAlertsTable alerts={filteredAlerts} loading={loadingAlerts} />
          </SectionCard>

          <SectionCard title="Latest Attack Chain" icon={Boxes}>
            {!latestChain ? (
              <div className="text-sm text-slate-500">No chain alert available yet.</div>
            ) : (
              <LatestAttackChain alert={latestChain} />
            )}
          </SectionCard>

          <SectionCard title="Top Alert Types" icon={Server} contentClassName="space-y-3">
            {topTypes.length === 0 ? (
              <div className="text-sm text-slate-500">No alert stats yet.</div>
            ) : (
              topTypes.map((item) => (
                <div
                  key={item.alert_type}
                  className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                >
                  <div className="min-w-0 pr-3 text-sm font-medium text-slate-800">{item.alert_type}</div>
                  <Badge variant="outline" className="rounded-full">{item.count}</Badge>
                </div>
              ))
            )}
          </SectionCard>
        </div>
      </div>
    </>
  );
}

function LatestAttackChain({ alert }: { alert: SecurityAlert }) {
  return (
    <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={alert.severity} />
        <Badge variant="outline" className="rounded-full">{alert.alert_type}</Badge>
        {alert.source_event?.pod_name ? (
          <Badge variant="outline" className="rounded-full">
            pod:{alert.source_event.pod_name}
          </Badge>
        ) : null}
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700">
        <span className="font-medium text-slate-900">Attack Chain:</span> {buildAttackSummary(alert)}
      </div>

      <div className="text-sm text-slate-700">
        <div><span className="font-medium text-slate-900">When:</span> {formatTs(alert.ts)}</div>
        <div><span className="font-medium text-slate-900">Process:</span> {alert.source_event?.comm || "-"}</div>
        <div><span className="font-medium text-slate-900">Namespace:</span> {alert.source_event?.namespace || "-"}</div>
        <div><span className="font-medium text-slate-900">Pod:</span> {alert.source_event?.pod_name || "-"}</div>
        <div><span className="font-medium text-slate-900">Container:</span> {alert.source_event?.container_name || "-"}</div>
        <div><span className="font-medium text-slate-900">Runtime:</span> {alert.source_event?.runtime || "-"}</div>
        <div><span className="font-medium text-slate-900">Resolver:</span> {alert.source_event?.resolver_status || "-"}</div>
        <div><span className="font-medium text-slate-900">Destination:</span> {alert.details?.destination || "-"}</div>
        <div><span className="font-medium text-slate-900">Sensitive File:</span> {alert.details?.triggering_open?.filename || "-"}</div>
        <div><span className="font-medium text-slate-900">Exec:</span> {alert.details?.triggering_exec?.filename || "-"}</div>
      </div>
    </div>
  );
}

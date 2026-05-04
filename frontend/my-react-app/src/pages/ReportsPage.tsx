import { BarChart3, FileText, ListChecks, TrendingUp } from "lucide-react";
import { useMemo } from "react";

import { AlertsBySeverityChart } from "@/components/charts/AlertsBySeverityChart";
import { EventsByTypeChart } from "@/components/charts/EventsByTypeChart";
import { RiskTrendChart } from "@/components/charts/RiskTrendChart";
import { TopPodsRiskChart } from "@/components/charts/TopPodsRiskChart";
import { SectionCard } from "@/components/common/SectionCard";
import { StatCard } from "@/components/common/StatCard";
import { SecurityFilters } from "@/components/filters/SecurityFilters";
import { PageHeader } from "@/components/layout/PageHeader";
import type { SecurityAlert } from "@/types/alerts";
import type { SecurityFilters as SecurityFiltersValue } from "@/types/filters";
import type { ContainerRisk } from "@/types/risk";
import {
  applySecurityFilters,
  formatTrendSummary,
  getAlertFilterFields,
  getAlertsBySeverityData,
  getEventsByTypeData,
  getRiskFilterFields,
  getRiskTrendData,
  getTopPodsRiskData,
} from "@/utils/analytics";

type ReportsPageProps = {
  alerts: SecurityAlert[];
  filters: SecurityFiltersValue;
  onFiltersChange: (filters: SecurityFiltersValue) => void;
  riskItems: ContainerRisk[];
};

export function ReportsPage({ alerts, filters, onFiltersChange, riskItems }: ReportsPageProps) {
  const filteredAlerts = useMemo(
    () => applySecurityFilters(alerts, filters, getAlertFilterFields),
    [alerts, filters],
  );

  const filteredRisk = useMemo(
    () => applySecurityFilters(riskItems, filters, getRiskFilterFields),
    [riskItems, filters],
  );

  const severityData = useMemo(
    () => getAlertsBySeverityData(null, filteredAlerts),
    [filteredAlerts],
  );
  const typeData = useMemo(
    () => getEventsByTypeData(null, filteredAlerts),
    [filteredAlerts],
  );
  const riskTrendData = useMemo(() => getRiskTrendData(filteredRisk), [filteredRisk]);
  const topPodsData = useMemo(() => getTopPodsRiskData(filteredRisk), [filteredRisk]);
  const averageRisk =
    filteredRisk.length === 0
      ? 0
      : Math.round(
          filteredRisk.reduce((total, item) => total + Number(item.final_risk_score ?? 0), 0) /
            filteredRisk.length,
        );

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileText}
        title="Security Reports"
        description="Filtered analytics from the existing alerts and container-risk API responses."
      />

      <SecurityFilters value={filters} onChange={onFiltersChange} />

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard title="Filtered Alerts" value={filteredAlerts.length} icon={ListChecks} />
        <StatCard title="Average Risk By Pod" value={averageRisk} icon={BarChart3} />
        <StatCard title="Trend Summary" value={riskTrendData.length} icon={TrendingUp} hint={formatTrendSummary(filteredRisk)} />
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <AlertsBySeverityChart data={severityData} />
        <EventsByTypeChart data={typeData} />
        <RiskTrendChart data={riskTrendData} />
        <TopPodsRiskChart data={topPodsData} />
      </div>

      <SectionCard title="Top Risky Pods" icon={BarChart3} contentClassName="space-y-3">
        {topPodsData.length === 0 ? (
          <div className="text-sm text-slate-500">No pod risk data matches the current filters.</div>
        ) : (
          topPodsData.map((item) => (
            <div
              key={item.pod}
              className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
            >
              <div className="min-w-0 pr-3 text-sm font-medium text-slate-800">{item.pod}</div>
              <div className="text-sm font-semibold text-slate-950">{item.risk}</div>
            </div>
          ))
        )}
      </SectionCard>
    </div>
  );
}

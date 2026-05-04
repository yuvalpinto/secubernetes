import type { AlertSeverity, AlertSummary, SecurityAlert } from "@/types/alerts";
import type { ContainerRisk } from "@/types/risk";
import type { SecurityFilters } from "@/types/filters";

export type SeverityChartDatum = {
  severity: string;
  count: number;
};

export type TypeChartDatum = {
  type: string;
  count: number;
};

export type RiskTrendDatum = {
  label: string;
  risk: number;
};

export type PodRiskDatum = {
  pod: string;
  risk: number;
};

const severityOrder = ["critical", "high", "medium", "low"];

export function getAlertsBySeverityData(summary: AlertSummary | null, alerts: SecurityAlert[]) {
  const bySeverity = summary?.by_severity;

  if (bySeverity && Object.keys(bySeverity).length > 0) {
    const known = severityOrder.map((severity) => ({
      severity,
      count: bySeverity[severity] ?? 0,
    }));
    const extra = Object.entries(bySeverity)
      .filter(([severity]) => !severityOrder.includes(severity))
      .map(([severity, count]) => ({ severity, count }));

    return [...known, ...extra].filter((item) => item.count > 0);
  }

  const counts = countBy(alerts, (alert) => alert.severity || "unknown");
  return Object.entries(counts).map(([severity, count]) => ({ severity, count }));
}

export function getEventsByTypeData(summary: AlertSummary | null, alerts: SecurityAlert[]) {
  if (summary?.top_alert_types?.length) {
    return summary.top_alert_types.map((item) => ({
      type: item.alert_type,
      count: item.count,
    }));
  }

  return Object.entries(countBy(alerts, (alert) => alert.alert_type || alert.event_type || "unknown"))
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
}

export function getRiskTrendData(riskItems: ContainerRisk[]) {
  return [...riskItems]
    .filter((item) => item.ts && typeof item.final_risk_score === "number")
    .sort((a, b) => new Date(a.ts || "").getTime() - new Date(b.ts || "").getTime())
    .slice(-20)
    .map((item) => ({
      label: formatShortTime(item.ts),
      risk: Number(item.final_risk_score ?? 0),
    }));
}

export function getTopPodsRiskData(riskItems: ContainerRisk[], limit = 8) {
  const grouped = new Map<string, { total: number; count: number; max: number }>();

  riskItems.forEach((item) => {
    const pod = item.pod_name || "unknown";
    const risk = Number(item.final_risk_score ?? 0);
    const current = grouped.get(pod) || { total: 0, count: 0, max: 0 };
    grouped.set(pod, {
      total: current.total + risk,
      count: current.count + 1,
      max: Math.max(current.max, risk),
    });
  });

  return [...grouped.entries()]
    .map(([pod, value]) => ({
      pod,
      risk: Math.round(value.total / Math.max(value.count, 1)),
    }))
    .sort((a, b) => b.risk - a.risk)
    .slice(0, limit);
}

export function applySecurityFilters<T extends SecurityEventLike>(
  items: T[],
  filters: SecurityFilters,
  getFields: (item: T) => SecurityFilterFields,
) {
  const now = Date.now();
  const oldestAllowed = getOldestAllowed(filters.timeRange, now);
  const podQuery = filters.podName.trim().toLowerCase();
  const namespaceQuery = filters.namespace.trim().toLowerCase();

  return items.filter((item) => {
    const fields = getFields(item);
    const pod = (fields.podName || "").toLowerCase();
    const namespace = (fields.namespace || "").toLowerCase();
    const severity = fields.severity || "unknown";
    const ts = fields.ts ? new Date(fields.ts).getTime() : Number.NaN;

    if (podQuery && !pod.includes(podQuery)) return false;
    if (namespaceQuery && !namespace.includes(namespaceQuery)) return false;
    if (filters.severity !== "all" && severity !== filters.severity) return false;
    if (oldestAllowed !== null && (!Number.isFinite(ts) || ts < oldestAllowed)) return false;

    return true;
  });
}

export function getAlertFilterFields(alert: SecurityAlert): SecurityFilterFields {
  return {
    namespace: alert.source_event?.namespace,
    podName: alert.source_event?.pod_name,
    severity: alert.severity || undefined,
    ts: alert.ts,
  };
}

export function getRiskFilterFields(item: ContainerRisk): SecurityFilterFields {
  return {
    namespace: item.namespace,
    podName: item.pod_name,
    severity: item.final_risk_level as AlertSeverity | undefined,
    ts: item.ts,
  };
}

export function formatTrendSummary(riskItems: ContainerRisk[]) {
  const trend = getRiskTrendData(riskItems);
  if (trend.length < 2) return "Not enough risk history yet.";

  const first = trend[0].risk;
  const last = trend[trend.length - 1].risk;
  const delta = last - first;

  if (delta > 0) return `Risk is up ${delta} points across the current sample.`;
  if (delta < 0) return `Risk is down ${Math.abs(delta)} points across the current sample.`;
  return "Risk is steady across the current sample.";
}

type SecurityEventLike = Record<string, unknown>;

type SecurityFilterFields = {
  namespace?: string | null;
  podName?: string | null;
  severity?: AlertSeverity | null;
  ts?: string | null;
};

function countBy<T>(items: T[], getKey: (item: T) => string) {
  return items.reduce<Record<string, number>>((acc, item) => {
    const key = getKey(item);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function formatShortTime(ts?: string | null) {
  if (!ts) return "-";
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return ts;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function getOldestAllowed(timeRange: SecurityFilters["timeRange"], now: number) {
  switch (timeRange) {
    case "15m":
      return now - 15 * 60 * 1000;
    case "1h":
      return now - 60 * 60 * 1000;
    case "6h":
      return now - 6 * 60 * 60 * 1000;
    case "24h":
      return now - 24 * 60 * 60 * 1000;
    case "7d":
      return now - 7 * 24 * 60 * 60 * 1000;
    case "all":
      return null;
  }
}

import React, { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  Activity,
  Network,
  Search,
  RefreshCw,
  Filter,
  Clock3,
  Server,
  Bug,
  Boxes,
  BarChart3,
  Radar,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const API_BASE = "http://127.0.0.1:8000";

const severityStyles: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
  low: "bg-blue-100 text-blue-800 border-blue-200",
};

const riskLevelStyles: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
  low: "bg-blue-100 text-blue-800 border-blue-200",
};

const endpointOptions = [
  { label: "Latest Alerts", value: "latest", path: "/alerts/latest?limit=50" },
  { label: "Chain Alerts", value: "chains", path: "/alerts/chains?limit=50" },
  { label: "Critical Alerts", value: "critical", path: "/alerts/by-severity/critical?limit=50" },
  { label: "High Alerts", value: "high", path: "/alerts/by-severity/high?limit=50" },
  { label: "Medium Alerts", value: "medium", path: "/alerts/by-severity/medium?limit=50" },
  { label: "Low Alerts", value: "low", path: "/alerts/by-severity/low?limit=50" },
];

const riskEndpointOptions = [
  { label: "Latest Risk Feed", value: "latest", path: "/container-risk/latest?limit=50" },
  { label: "Latest Risk Per Pod", value: "latest-per-pod", path: "/container-risk/latest-per-pod?limit=50" },
  { label: "Risk By Pod", value: "by-pod", path: "" },
];

function StatCard({
  title,
  value,
  icon: Icon,
  hint,
}: {
  title: string;
  value: React.ReactNode;
  icon: any;
  hint?: string;
}) {
  return (
    <Card className="rounded-2xl border-slate-200 shadow-sm">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-sm text-slate-500">{title}</div>
            <div className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">
              {value ?? "-"}
            </div>
            {hint ? <div className="mt-2 text-xs text-slate-500">{hint}</div> : null}
          </div>
          <div className="rounded-2xl bg-slate-100 p-3">
            <Icon className="h-5 w-5 text-slate-700" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function SeverityBadge({ severity }: { severity?: string }) {
  const cls = severityStyles[severity || ""] || "bg-slate-100 text-slate-800 border-slate-200";
  return <Badge className={`border ${cls}`}>{severity || "unknown"}</Badge>;
}

function RiskLevelBadge({ level }: { level?: string }) {
  const cls = riskLevelStyles[level || ""] || "bg-slate-100 text-slate-800 border-slate-200";
  return <Badge className={`border ${cls}`}>{level || "unknown"}</Badge>;
}

function SectionTitle({ icon: Icon, children }: { icon: any; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="h-5 w-5 text-slate-700" />
      <h2 className="text-lg font-semibold tracking-tight text-slate-900">{children}</h2>
    </div>
  );
}

function formatTs(ts?: string | null) {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function truncateMiddle(value?: string | null, start = 12, end = 8) {
  if (!value) return "-";
  if (value.length <= start + end + 3) return value;
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}

function formatDurationSeconds(value?: number | null) {
  if (value === undefined || value === null) return "-";
  return `${value}s`;
}

function buildAttackSummary(alert: any) {
  const details = alert?.details || {};
  const source = alert?.source_event || {};

  const execName =
    details?.triggering_exec?.filename ||
    details?.triggering_exec?.comm ||
    "-";

  const openName =
    details?.triggering_open?.filename ||
    source?.filename ||
    "-";

  const destination =
    details?.destination ||
    (details?.destination_ip && details?.destination_port
      ? `${details.destination_ip}:${details.destination_port}`
      : source?.ip && source?.port
      ? `${source.ip}:${source.port}`
      : "-");

  if (alert?.alert_type === "sensitive_access_and_exfiltration_chain") {
    return `${execName} → ${openName} → ${destination}`;
  }

  if (alert?.alert_type === "root_sensitive_access_then_connect") {
    return `${openName} → ${destination}`;
  }

  if (alert?.alert_type === "sensitive_access_then_connect") {
    return `${openName} → ${destination}`;
  }

  return "-";
}

function KubernetesContext({ source }: { source: any }) {
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

function AlertRow({ alert }: { alert: any }) {
  const details = alert?.details || {};
  const source = alert?.source_event || {};
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
            <SeverityBadge severity={alert?.severity} />
            <Badge variant="outline" className="rounded-full">{alert?.alert_type || "unknown_alert"}</Badge>
            <Badge variant="outline" className="rounded-full">{alert?.event_type || "unknown_event"}</Badge>
            {source?.pod_name ? (
              <Badge variant="outline" className="rounded-full">
                pod:{source.pod_name}
              </Badge>
            ) : null}
            {source?.namespace ? (
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
            <div><span className="font-medium text-slate-900">Lineage:</span> {alert?.lineage_summary || "-"}</div>
            <div><span className="font-medium text-slate-900">Time:</span> {formatTs(alert?.ts)}</div>

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

          {(details.triggering_open || details.triggering_exec) ? (
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
          ) : null}
        </div>
      </div>
    </motion.div>
  );
}

function RiskRow({ item }: { item: any }) {
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
            <RiskLevelBadge level={item?.final_risk_level} />
            <Badge variant="outline" className="rounded-full">
              score:{item?.final_risk_score ?? "-"}
            </Badge>
            {item?.pod_name ? (
              <Badge variant="outline" className="rounded-full">
                pod:{item.pod_name}
              </Badge>
            ) : null}
            {item?.namespace ? (
              <Badge variant="outline" className="rounded-full">
                ns:{item.namespace}
              </Badge>
            ) : null}
          </div>

          <div className="grid gap-2 text-sm text-slate-700 md:grid-cols-2 xl:grid-cols-4">
            <div><span className="font-medium text-slate-900">Time:</span> {formatTs(item?.ts)}</div>
            <div><span className="font-medium text-slate-900">Window Start:</span> {formatTs(item?.window_start)}</div>
            <div><span className="font-medium text-slate-900">Window End:</span> {formatTs(item?.window_end)}</div>
            <div><span className="font-medium text-slate-900">Container ID:</span> {truncateMiddle(item?.container_id, 12, 6)}</div>

            <div><span className="font-medium text-slate-900">Sequence Score:</span> {item?.sequence_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">Stat Score:</span> {item?.stat_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">LOF Score:</span> {item?.lof_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">Alerts Count:</span> {item?.alerts_count ?? 0}</div>

            <div><span className="font-medium text-slate-900">Max Alert:</span> {item?.max_alert?.alert_type || item?.max_alert || "-"}</div>
            <div><span className="font-medium text-slate-900">Threshold Anomaly:</span> {String(!!item?.threshold_anomaly_detected)}</div>
            <div><span className="font-medium text-slate-900">Threshold Z:</span> {item?.threshold_max_z_score ?? 0}</div>
            <div><span className="font-medium text-slate-900">LOF Value:</span> {item?.lof_value ?? 0}</div>

            <div><span className="font-medium text-slate-900">Exec Count:</span> {item?.exec_count_window ?? 0}</div>
            <div><span className="font-medium text-slate-900">Sensitive Opens:</span> {item?.sensitive_open_count_window ?? 0}</div>
            <div><span className="font-medium text-slate-900">Connect Count:</span> {item?.connect_count_window ?? 0}</div>
            <div><span className="font-medium text-slate-900">Unique Dests:</span> {item?.unique_destination_count_window ?? 0}</div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export default function SecubernetesDashboard() {
  const [summary, setSummary] = useState<any>(null);
  const [alertsPayload, setAlertsPayload] = useState<any>({ items: [], count: 0 });
  const [riskPayload, setRiskPayload] = useState<any>({ items: [], count: 0 });

  const [endpoint, setEndpoint] = useState("latest");
  const [riskEndpoint, setRiskEndpoint] = useState("latest");
  const [riskPodName, setRiskPodName] = useState("test-pod");
  const [search, setSearch] = useState("");

  const [loadingSummary, setLoadingSummary] = useState(true);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [loadingRisk, setLoadingRisk] = useState(true);

  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const selectedEndpoint =
    endpointOptions.find((item) => item.value === endpoint) || endpointOptions[0];

  const selectedRiskEndpoint =
    riskEndpointOptions.find((item) => item.value === riskEndpoint) || riskEndpointOptions[0];

  async function fetchSummary() {
    setLoadingSummary(true);
    try {
      const res = await fetch(`${API_BASE}/alerts/summary`);
      if (!res.ok) throw new Error(`Summary request failed: ${res.status}`);
      const data = await res.json();
      setSummary(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load summary");
    } finally {
      setLoadingSummary(false);
    }
  }

  async function fetchAlerts() {
    setLoadingAlerts(true);
    try {
      const res = await fetch(`${API_BASE}${selectedEndpoint.path}`);
      if (!res.ok) throw new Error(`Alerts request failed: ${res.status}`);
      const data = await res.json();
      setAlertsPayload(data);
      setError("");
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alerts");
    } finally {
      setLoadingAlerts(false);
    }
  }

  async function fetchRisk() {
    setLoadingRisk(true);
    try {
      let url = "";

      if (riskEndpoint === "by-pod") {
        const pod = riskPodName.trim();
        if (!pod) {
          setRiskPayload({ items: [], count: 0 });
          setLoadingRisk(false);
          return;
        }
        url = `${API_BASE}/container-risk/by-pod/${encodeURIComponent(pod)}?limit=50`;
      } else {
        url = `${API_BASE}${selectedRiskEndpoint.path}`;
      }

      const res = await fetch(url);
      if (!res.ok) throw new Error(`Risk request failed: ${res.status}`);
      const data = await res.json();
      setRiskPayload(data);
      setError("");
      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load risk");
    } finally {
      setLoadingRisk(false);
    }
  }

  async function refreshAll() {
    await Promise.all([fetchSummary(), fetchAlerts(), fetchRisk()]);
  }

  useEffect(() => {
    refreshAll();
    const id = setInterval(refreshAll, 60000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [endpoint]);

  useEffect(() => {
    fetchRisk();
  }, [riskEndpoint, riskPodName]);

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();
    const items = alertsPayload?.items || [];
    if (!q) return items;

    return items.filter((alert: any) => {
      const haystack = JSON.stringify(alert).toLowerCase();
      return haystack.includes(q);
    });
  }, [alertsPayload, search]);

  const filteredRisk = useMemo(() => {
    const q = search.trim().toLowerCase();
    const items = riskPayload?.items || [];
    if (!q) return items;

    return items.filter((item: any) => {
      const haystack = JSON.stringify(item).toLowerCase();
      return haystack.includes(q);
    });
  }, [riskPayload, search]);

  const severityMap = summary?.by_severity || {};
  const topTypes = summary?.top_alert_types || [];
  const latestChain = summary?.latest_chain || null;

  const highestRisk = useMemo(() => {
    const items = riskPayload?.items || [];
    if (!items.length) return null;
    return [...items].sort((a, b) => (b.final_risk_score || 0) - (a.final_risk_score || 0))[0];
  }, [riskPayload]);

  const criticalRiskCount = useMemo(() => {
    return (riskPayload?.items || []).filter((item: any) => item?.final_risk_level === "critical").length;
  }, [riskPayload]);

  const highRiskCount = useMemo(() => {
    return (riskPayload?.items || []).filter((item: any) => item?.final_risk_level === "high").length;
  }, [riskPayload]);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
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
              Live visibility into alerts, attack chains, and per-pod risk scoring collected from execve, openat, connect, threshold, LOF, and sequence analysis.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm text-slate-600 shadow-sm">
              Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "-"}
            </div>
            <Button onClick={refreshAll} className="rounded-2xl">
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
        </motion.div>

        {error ? (
          <div className="mb-6 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
            {error}
          </div>
        ) : null}

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <StatCard title="Total Alerts" value={loadingSummary ? "..." : summary?.total_alerts ?? 0} icon={AlertTriangle} />
          <StatCard title="Critical Alerts" value={loadingSummary ? "..." : severityMap.critical ?? 0} icon={Bug} />
          <StatCard title="High Alerts" value={loadingSummary ? "..." : severityMap.high ?? 0} icon={Shield} />
          <StatCard title="Critical Risk Rows" value={loadingRisk ? "..." : criticalRiskCount} icon={Radar} />
          <StatCard title="High Risk Rows" value={loadingRisk ? "..." : highRiskCount} icon={BarChart3} />
        </div>

        <div className="mt-8 grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <Card className="rounded-2xl border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle>
                <SectionTitle icon={Radar}>Container Risk Feed</SectionTitle>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 lg:grid-cols-[1fr_220px_220px_auto]">
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                  <Input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search pod, namespace, risk, detector values, alert type..."
                    className="rounded-2xl pl-9"
                  />
                </div>

                <Select value={riskEndpoint} onValueChange={setRiskEndpoint}>
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
                  onChange={(e) => setRiskPodName(e.target.value)}
                  placeholder="Pod name"
                  className="rounded-2xl"
                  disabled={riskEndpoint !== "by-pod"}
                />

                <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-2 text-sm text-slate-600">
                  Showing {filteredRisk.length} / {riskPayload?.count ?? 0}
                </div>
              </div>

              <div className="space-y-3">
                {loadingRisk ? (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 text-sm text-slate-500">
                    Loading risk scores...
                  </div>
                ) : filteredRisk.length === 0 ? (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 text-sm text-slate-500">
                    No risk scores available yet.
                  </div>
                ) : (
                  filteredRisk.map((item: any) => (
                    <RiskRow
                      key={item._id || `${item.namespace}-${item.pod_name}-${item.ts}`}
                      item={item}
                    />
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          <div className="space-y-6">
            <Card className="rounded-2xl border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle>
                  <SectionTitle icon={Server}>Highest Current Risk</SectionTitle>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!highestRisk ? (
                  <div className="text-sm text-slate-500">No risk scores yet.</div>
                ) : (
                  <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <RiskLevelBadge level={highestRisk.final_risk_level} />
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
                      <div><span className="font-medium text-slate-900">Max Alert:</span> {highestRisk.max_alert?.alert_type || highestRisk.max_alert || "-"}</div>
                      <div><span className="font-medium text-slate-900">Time:</span> {formatTs(highestRisk.ts)}</div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="rounded-2xl border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle>
                  <SectionTitle icon={Network}>Alert Feed</SectionTitle>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 lg:grid-cols-[1fr_220px_auto]">
                  <div />
                  <Select value={endpoint} onValueChange={setEndpoint}>
                    <SelectTrigger className="rounded-2xl">
                      <div className="flex items-center gap-2">
                        <Filter className="h-4 w-4" />
                        <SelectValue placeholder="Choose feed" />
                      </div>
                    </SelectTrigger>
                    <SelectContent>
                      {endpointOptions.map((item) => (
                        <SelectItem key={item.value} value={item.value}>
                          {item.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-2 text-sm text-slate-600">
                    Showing {filteredAlerts.length} / {alertsPayload?.count ?? 0}
                  </div>
                </div>

                <div className="space-y-3">
                  {loadingAlerts ? (
                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 text-sm text-slate-500">
                      Loading alerts...
                    </div>
                  ) : filteredAlerts.length === 0 ? (
                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 text-sm text-slate-500">
                      No alerts match the current filter.
                    </div>
                  ) : (
                    filteredAlerts.map((alert: any) => (
                      <AlertRow key={alert._id?.$oid || alert._id || `${alert.alert_type}-${alert.ts}`} alert={alert} />
                    ))
                  )}
                </div>
              </CardContent>
            </Card>

            <Card className="rounded-2xl border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle>
                  <SectionTitle icon={Boxes}>Latest Attack Chain</SectionTitle>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!latestChain ? (
                  <div className="text-sm text-slate-500">No chain alert available yet.</div>
                ) : (
                  <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={latestChain.severity} />
                      <Badge variant="outline" className="rounded-full">{latestChain.alert_type}</Badge>
                      {latestChain?.source_event?.pod_name ? (
                        <Badge variant="outline" className="rounded-full">
                          pod:{latestChain.source_event.pod_name}
                        </Badge>
                      ) : null}
                    </div>

                    <div className="rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700">
                      <span className="font-medium text-slate-900">Attack Chain:</span> {buildAttackSummary(latestChain)}
                    </div>

                    <div className="text-sm text-slate-700">
                      <div><span className="font-medium text-slate-900">When:</span> {formatTs(latestChain.ts)}</div>
                      <div><span className="font-medium text-slate-900">Process:</span> {latestChain?.source_event?.comm || "-"}</div>
                      <div><span className="font-medium text-slate-900">Namespace:</span> {latestChain?.source_event?.namespace || "-"}</div>
                      <div><span className="font-medium text-slate-900">Pod:</span> {latestChain?.source_event?.pod_name || "-"}</div>
                      <div><span className="font-medium text-slate-900">Container:</span> {latestChain?.source_event?.container_name || "-"}</div>
                      <div><span className="font-medium text-slate-900">Runtime:</span> {latestChain?.source_event?.runtime || "-"}</div>
                      <div><span className="font-medium text-slate-900">Resolver:</span> {latestChain?.source_event?.resolver_status || "-"}</div>
                      <div><span className="font-medium text-slate-900">Destination:</span> {latestChain?.details?.destination || "-"}</div>
                      <div><span className="font-medium text-slate-900">Sensitive File:</span> {latestChain?.details?.triggering_open?.filename || "-"}</div>
                      <div><span className="font-medium text-slate-900">Exec:</span> {latestChain?.details?.triggering_exec?.filename || "-"}</div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="rounded-2xl border-slate-200 shadow-sm">
              <CardHeader>
                <CardTitle>
                  <SectionTitle icon={Server}>Top Alert Types</SectionTitle>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {topTypes.length === 0 ? (
                  <div className="text-sm text-slate-500">No alert stats yet.</div>
                ) : (
                  topTypes.map((item: any) => (
                    <div
                      key={item.alert_type}
                      className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                    >
                      <div className="min-w-0 pr-3 text-sm font-medium text-slate-800">{item.alert_type}</div>
                      <Badge variant="outline" className="rounded-full">{item.count}</Badge>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
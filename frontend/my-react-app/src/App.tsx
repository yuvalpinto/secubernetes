import { useEffect, useState } from "react";

import { getAlertSummary, getAlertsByEndpoint } from "@/api/alertsApi";
import { getRiskByEndpoint } from "@/api/riskApi";
import { ErrorState } from "@/components/common/ErrorState";
import { DashboardHeader } from "@/components/layout/DashboardHeader";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { SidebarNav, type AppPage } from "@/components/layout/SidebarNav";
import { DashboardPage } from "@/pages/DashboardPage";
import { PolicyPage } from "@/pages/PolicyPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { SupplyChainPage } from "@/pages/SupplyChainPage";
import type { AlertEndpointValue, AlertListResponse, AlertSummary } from "@/types/alerts";
import type { SecurityFilters } from "@/types/filters";
import type { RiskEndpointValue, RiskListResponse } from "@/types/risk";

const defaultFilters: SecurityFilters = {
  namespace: "",
  podName: "",
  search: "",
  severity: "all",
  timeRange: "all",
};

export default function SecubernetesDashboard() {
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [alertsPayload, setAlertsPayload] = useState<AlertListResponse>({ items: [], count: 0 });
  const [riskPayload, setRiskPayload] = useState<RiskListResponse>({ items: [], count: 0 });

  const [endpoint, setEndpoint] = useState<AlertEndpointValue>("latest");
  const [riskEndpoint, setRiskEndpoint] = useState<RiskEndpointValue>("latest");
  const [riskPodName, setRiskPodName] = useState("test-pod");
  const [search, setSearch] = useState("");
  const [activePage, setActivePage] = useState<AppPage>("dashboard");
  const [reportFilters, setReportFilters] = useState<SecurityFilters>(defaultFilters);

  const [loadingSummary, setLoadingSummary] = useState(true);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [loadingRisk, setLoadingRisk] = useState(true);

  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  async function fetchSummary() {
    setLoadingSummary(true);
    try {
      const data = await getAlertSummary();
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
      const data = await getAlertsByEndpoint(endpoint);
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
      if (riskEndpoint === "by-pod") {
        const pod = riskPodName.trim();
        if (!pod) {
          setRiskPayload({ items: [], count: 0 });
          return;
        }
      }

      const data = await getRiskByEndpoint(riskEndpoint, riskPodName.trim());
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

  function renderPage() {
    switch (activePage) {
      case "policy":
        return <PolicyPage />;
      case "supply-chain":
        return <SupplyChainPage />;
      case "reports":
        return (
          <ReportsPage
            alerts={alertsPayload.items}
            filters={reportFilters}
            onFiltersChange={setReportFilters}
            riskItems={riskPayload.items}
          />
        );
      case "dashboard":
        return (
          <DashboardPage
            alertsPayload={alertsPayload}
            endpoint={endpoint}
            loadingAlerts={loadingAlerts}
            loadingRisk={loadingRisk}
            loadingSummary={loadingSummary}
            onEndpointChange={setEndpoint}
            onRiskEndpointChange={setRiskEndpoint}
            onRiskPodNameChange={setRiskPodName}
            onSearchChange={setSearch}
            riskEndpoint={riskEndpoint}
            riskPayload={riskPayload}
            riskPodName={riskPodName}
            search={search}
            summary={summary}
          />
        );
    }
  }

  return (
    <DashboardLayout>
      <DashboardHeader lastUpdated={lastUpdated} onRefresh={refreshAll} />
      <div className="mb-6">
        <SidebarNav activePage={activePage} onPageChange={setActivePage} />
      </div>
      <ErrorState message={error} />
      {renderPage()}
    </DashboardLayout>
  );
}

import { apiGet } from "./client";
import type {
  AlertEndpointOption,
  AlertEndpointValue,
  AlertListResponse,
  AlertSeverity,
  AlertSummary,
} from "@/types/alerts";

export const alertEndpointOptions: AlertEndpointOption[] = [
  { label: "Latest Alerts", value: "latest", path: "/alerts/latest?limit=50" },
  { label: "Chain Alerts", value: "chains", path: "/alerts/chains?limit=50" },
  { label: "Critical Alerts", value: "critical", path: "/alerts/by-severity/critical?limit=50" },
  { label: "High Alerts", value: "high", path: "/alerts/by-severity/high?limit=50" },
  { label: "Medium Alerts", value: "medium", path: "/alerts/by-severity/medium?limit=50" },
  { label: "Low Alerts", value: "low", path: "/alerts/by-severity/low?limit=50" },
];

export function getAlertSummary() {
  return apiGet<AlertSummary>("/alerts/summary", "Summary");
}

export function getAlertsByEndpoint(endpoint: AlertEndpointValue) {
  const selectedEndpoint =
    alertEndpointOptions.find((item) => item.value === endpoint) || alertEndpointOptions[0];

  return apiGet<AlertListResponse>(selectedEndpoint.path, "Alerts");
}

export function getLatestAlerts(limit = 50) {
  return apiGet<AlertListResponse>(`/alerts/latest?limit=${limit}`, "Alerts");
}

export function getChainAlerts(limit = 50) {
  return apiGet<AlertListResponse>(`/alerts/chains?limit=${limit}`, "Alerts");
}

export function getAlertsBySeverity(severity: AlertSeverity, limit = 50) {
  return apiGet<AlertListResponse>(
    `/alerts/by-severity/${encodeURIComponent(severity)}?limit=${limit}`,
    "Alerts",
  );
}

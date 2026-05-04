import { apiGet } from "./client";
import type { RiskEndpointOption, RiskEndpointValue, RiskListResponse } from "@/types/risk";

export const riskEndpointOptions: RiskEndpointOption[] = [
  { label: "Latest Risk Feed", value: "latest", path: "/container-risk/latest?limit=50" },
  { label: "Latest Risk Per Pod", value: "latest-per-pod", path: "/container-risk/latest-per-pod?limit=50" },
  { label: "Risk By Pod", value: "by-pod", path: "" },
];

export function getRiskByEndpoint(endpoint: RiskEndpointValue, podName: string) {
  if (endpoint === "by-pod") {
    return getRiskByPod(podName);
  }

  const selectedEndpoint =
    riskEndpointOptions.find((item) => item.value === endpoint) || riskEndpointOptions[0];

  return apiGet<RiskListResponse>(selectedEndpoint.path, "Risk");
}

export function getLatestRisk(limit = 50) {
  return apiGet<RiskListResponse>(`/container-risk/latest?limit=${limit}`, "Risk");
}

export function getLatestRiskPerPod(limit = 50) {
  return apiGet<RiskListResponse>(`/container-risk/latest-per-pod?limit=${limit}`, "Risk");
}

export function getRiskByPod(podName: string, limit = 50) {
  return apiGet<RiskListResponse>(
    `/container-risk/by-pod/${encodeURIComponent(podName)}?limit=${limit}`,
    "Risk",
  );
}

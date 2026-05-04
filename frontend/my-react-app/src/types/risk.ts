import type { ApiListResponse } from "./common";

export type RiskLevel = "critical" | "high" | "medium" | "low" | (string & {});

export type RiskEndpointValue = "latest" | "latest-per-pod" | "by-pod";

export type RiskEndpointOption = {
  label: string;
  value: RiskEndpointValue;
  path: string;
};

export type RiskAlertReference =
  | string
  | {
      alert_type?: string | null;
      severity?: string | null;
      [key: string]: unknown;
    };

export type ContainerRisk = {
  _id?: string;
  alerts_count?: number | null;
  connect_count_window?: number | null;
  container_id?: string | null;
  exec_count_window?: number | null;
  final_risk_level?: RiskLevel | null;
  final_risk_score?: number | null;
  lof_score?: number | null;
  lof_value?: number | null;
  max_alert?: RiskAlertReference | null;
  namespace?: string | null;
  pod_name?: string | null;
  sensitive_open_count_window?: number | null;
  sequence_score?: number | null;
  stat_score?: number | null;
  threshold_anomaly_detected?: boolean | null;
  threshold_max_z_score?: number | null;
  ts?: string | null;
  unique_destination_count_window?: number | null;
  window_end?: string | null;
  window_start?: string | null;
  [key: string]: unknown;
};

export type RiskListResponse = ApiListResponse<ContainerRisk>;

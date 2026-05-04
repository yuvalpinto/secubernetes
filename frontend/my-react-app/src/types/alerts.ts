import type { ApiListResponse, MongoObjectId } from "./common";

export type AlertSeverity = "critical" | "high" | "medium" | "low" | (string & {});

export type AlertEndpointValue =
  | "latest"
  | "chains"
  | "critical"
  | "high"
  | "medium"
  | "low";

export type AlertEndpointOption = {
  label: string;
  value: AlertEndpointValue;
  path: string;
};

export type KubernetesSourceEvent = {
  comm?: string | null;
  container_id?: string | null;
  container_name?: string | null;
  filename?: string | null;
  ip?: string | null;
  namespace?: string | null;
  pid?: number | null;
  pod_name?: string | null;
  pod_uid?: string | null;
  port?: number | null;
  resolver_status?: string | null;
  ret?: number | null;
  runtime?: string | null;
  success?: boolean | null;
  [key: string]: unknown;
};

export type TriggeringEvent = {
  comm?: string | null;
  container_id?: string | null;
  filename?: string | null;
  matched_rule?: string | null;
  pid?: number | null;
  [key: string]: unknown;
};

export type AlertDetails = {
  correlation_window_seconds?: number | null;
  destination?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  time_since_exec_seconds?: number | null;
  time_since_sensitive_open_seconds?: number | null;
  triggering_exec?: TriggeringEvent | null;
  triggering_open?: TriggeringEvent | null;
  [key: string]: unknown;
};

export type SecurityAlert = {
  _id?: string | MongoObjectId;
  alert_type?: string | null;
  details?: AlertDetails | null;
  event_type?: string | null;
  lineage_summary?: string | null;
  severity?: AlertSeverity | null;
  source_event?: KubernetesSourceEvent | null;
  ts?: string | null;
  [key: string]: unknown;
};

export type AlertListResponse = ApiListResponse<SecurityAlert>;

export type AlertTypeCount = {
  alert_type: string;
  count: number;
};

export type AlertSummary = {
  total_alerts?: number;
  by_severity?: Record<string, number>;
  top_alert_types?: AlertTypeCount[];
  latest_chain?: SecurityAlert | null;
  [key: string]: unknown;
};

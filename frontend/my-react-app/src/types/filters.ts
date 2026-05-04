import type { AlertSeverity } from "./alerts";
import type { TimeRange } from "./common";

export type SecurityFilters = {
  namespace: string;
  podName: string;
  search: string;
  severity: AlertSeverity | "all";
  timeRange: TimeRange;
};

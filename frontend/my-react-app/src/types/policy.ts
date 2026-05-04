import type { AlertSeverity } from "./alerts";

export type KyvernoBlockedPolicy = {
  id: string;
  namespace?: string | null;
  podName?: string | null;
  policyName?: string | null;
  ruleName?: string | null;
  severity?: AlertSeverity | null;
  timestamp?: string | null;
  message?: string | null;
};

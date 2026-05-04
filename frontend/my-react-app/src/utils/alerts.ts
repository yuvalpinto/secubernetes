import type { SecurityAlert } from "@/types/alerts";

export function buildAttackSummary(alert?: SecurityAlert | null) {
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

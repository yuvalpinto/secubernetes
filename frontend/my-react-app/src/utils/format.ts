export function formatTs(ts?: string | null) {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export function truncateMiddle(value?: string | null, start = 12, end = 8) {
  if (!value) return "-";
  if (value.length <= start + end + 3) return value;
  return `${value.slice(0, start)}...${value.slice(-end)}`;
}

export function formatDurationSeconds(value?: number | null) {
  if (value === undefined || value === null) return "-";
  return `${value}s`;
}

export function formatMaxAlert(value: unknown) {
  if (!value) return "-";
  if (typeof value === "string") return value;
  if (typeof value === "object" && "alert_type" in value) {
    const alertType = (value as { alert_type?: unknown }).alert_type;
    return typeof alertType === "string" && alertType ? alertType : "-";
  }
  return "-";
}

import { Filter } from "lucide-react";

import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { AlertSeverity } from "@/types/alerts";
import type { TimeRange } from "@/types/common";
import type { SecurityFilters as SecurityFiltersValue } from "@/types/filters";

type SecurityFiltersProps = {
  value: SecurityFiltersValue;
  onChange: (value: SecurityFiltersValue) => void;
};

const severityOptions = [
  { label: "All Severities", value: "all" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
];

const timeRangeOptions = [
  { label: "Last 15m", value: "15m" },
  { label: "Last 1h", value: "1h" },
  { label: "Last 6h", value: "6h" },
  { label: "Last 24h", value: "24h" },
  { label: "Last 7d", value: "7d" },
  { label: "All Time", value: "all" },
];

export function SecurityFilters({ value, onChange }: SecurityFiltersProps) {
  return (
    <div className="grid gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm md:grid-cols-2 xl:grid-cols-4">
      <div>
        <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
          Pod Name
        </label>
        <Input
          value={value.podName}
          onChange={(event) => onChange({ ...value, podName: event.target.value })}
          placeholder="Filter pod"
          className="rounded-2xl"
        />
      </div>

      <div>
        <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
          Namespace
        </label>
        <Input
          value={value.namespace}
          onChange={(event) => onChange({ ...value, namespace: event.target.value })}
          placeholder="Filter namespace"
          className="rounded-2xl"
        />
      </div>

      <div>
        <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
          Severity
        </label>
        <Select
          value={value.severity}
          onValueChange={(severity) =>
            onChange({ ...value, severity: severity as AlertSeverity | "all" })
          }
        >
          <SelectTrigger className="rounded-2xl">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" />
              <SelectValue placeholder="Severity" />
            </div>
          </SelectTrigger>
          <SelectContent>
            {severityOptions.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div>
        <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">
          Time Range
        </label>
        <Select
          value={value.timeRange}
          onValueChange={(timeRange) => onChange({ ...value, timeRange: timeRange as TimeRange })}
        >
          <SelectTrigger className="rounded-2xl">
            <SelectValue placeholder="Time range" />
          </SelectTrigger>
          <SelectContent>
            {timeRangeOptions.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}

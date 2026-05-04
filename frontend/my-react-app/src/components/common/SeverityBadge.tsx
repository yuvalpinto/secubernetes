import { Badge } from "@/components/ui/badge";

const severityStyles: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
  low: "bg-blue-100 text-blue-800 border-blue-200",
};

type SeverityBadgeProps = {
  severity?: string | null;
};

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const cls = severityStyles[severity || ""] || "bg-slate-100 text-slate-800 border-slate-200";
  return <Badge className={`border ${cls}`}>{severity || "unknown"}</Badge>;
}

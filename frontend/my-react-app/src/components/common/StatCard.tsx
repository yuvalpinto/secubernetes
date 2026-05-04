import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

type StatCardProps = {
  hint?: string;
  icon: LucideIcon;
  title: string;
  value: ReactNode;
};

export function StatCard({ title, value, icon: Icon, hint }: StatCardProps) {
  return (
    <Card className="rounded-2xl border-slate-200 shadow-sm">
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-sm text-slate-500">{title}</div>
            <div className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">
              {value ?? "-"}
            </div>
            {hint ? <div className="mt-2 text-xs text-slate-500">{hint}</div> : null}
          </div>
          <div className="rounded-2xl bg-slate-100 p-3">
            <Icon className="h-5 w-5 text-slate-700" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

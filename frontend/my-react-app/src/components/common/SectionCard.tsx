import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type SectionCardProps = {
  children: ReactNode;
  contentClassName?: string;
  icon: LucideIcon;
  title: string;
};

export function SectionCard({ children, contentClassName, icon: Icon, title }: SectionCardProps) {
  return (
    <Card className="rounded-2xl border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle>
          <div className="flex items-center gap-2">
            <Icon className="h-5 w-5 text-slate-700" />
            <h2 className="text-lg font-semibold tracking-tight text-slate-900">{title}</h2>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className={contentClassName}>{children}</CardContent>
    </Card>
  );
}

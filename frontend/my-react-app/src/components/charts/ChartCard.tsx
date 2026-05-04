import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

import { EmptyState } from "@/components/common/EmptyState";
import { SectionCard } from "@/components/common/SectionCard";

type ChartCardProps = {
  children: ReactNode;
  hasData: boolean;
  icon: LucideIcon;
  title: string;
};

export function ChartCard({ children, hasData, icon, title }: ChartCardProps) {
  return (
    <SectionCard title={title} icon={icon}>
      {hasData ? <div className="h-64">{children}</div> : <EmptyState message="No chart data available yet." />}
    </SectionCard>
  );
}

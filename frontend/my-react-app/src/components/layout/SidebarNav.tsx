import type { LucideIcon } from "lucide-react";
import { BarChart3, FileText, PackageCheck, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";

export type AppPage = "dashboard" | "policy" | "supply-chain" | "reports";

export type SidebarNavItem = {
  icon: LucideIcon;
  label: string;
  value: AppPage;
};

export const sidebarNavItems: SidebarNavItem[] = [
  { icon: BarChart3, label: "Dashboard", value: "dashboard" },
  { icon: ShieldCheck, label: "Policy", value: "policy" },
  { icon: PackageCheck, label: "Supply Chain", value: "supply-chain" },
  { icon: FileText, label: "Reports", value: "reports" },
];

type SidebarNavProps = {
  activePage: AppPage;
  onPageChange: (page: AppPage) => void;
};

export function SidebarNav({ activePage, onPageChange }: SidebarNavProps) {
  return (
    <nav className="flex flex-wrap gap-2">
      {sidebarNavItems.map((item) => {
        const Icon = item.icon;
        const isActive = item.value === activePage;

        return (
          <Button
            key={item.value}
            type="button"
            variant={isActive ? "default" : "outline"}
            onClick={() => onPageChange(item.value)}
          >
            <Icon className="h-4 w-4" />
            {item.label}
          </Button>
        );
      })}
    </nav>
  );
}

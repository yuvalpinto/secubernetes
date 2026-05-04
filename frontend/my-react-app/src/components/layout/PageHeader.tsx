import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

type PageHeaderProps = {
  actions?: ReactNode;
  children?: ReactNode;
  description?: string;
  icon?: LucideIcon;
  title: string;
};

export function PageHeader({ actions, children, description, icon: Icon, title }: PageHeaderProps) {
  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <div className="flex items-center gap-2">
          {Icon ? <Icon className="h-5 w-5 text-slate-700" /> : null}
          <h1 className="text-2xl font-semibold tracking-tight text-slate-950">{title}</h1>
        </div>
        {description ? <p className="mt-1 max-w-3xl text-sm text-slate-600">{description}</p> : null}
        {children}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

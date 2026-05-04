import { PackageCheck, ShieldCheck } from "lucide-react";

import { SectionCard } from "@/components/common/SectionCard";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge } from "@/components/ui/badge";

type SupplyChainEvidence = {
  detail: string;
  evidence: string;
  name: string;
  status: "allowed" | "blocked" | "passing" | "warning";
};

const fallbackSupplyChainEvidence: SupplyChainEvidence[] = [
  {
    name: "Cosign image signing status",
    status: "passing",
    detail: "Signed images validate against the configured public key identity.",
    evidence: "Local fallback/demo data",
  },
  {
    name: "Kyverno verifyImages enforcement",
    status: "passing",
    detail: "Admission policy requires signatures before workloads are admitted.",
    evidence: "Local fallback/demo data",
  },
  {
    name: "Trivy CVE scanning status",
    status: "warning",
    detail: "Image vulnerability scan status is surfaced for release review.",
    evidence: "Local fallback/demo data",
  },
  {
    name: "Signed image allowed",
    status: "allowed",
    detail: "A signed workload image is allowed through admission.",
    evidence: "Local fallback/demo data",
  },
  {
    name: "Unsigned image blocked",
    status: "blocked",
    detail: "An unsigned image is rejected by verifyImages enforcement.",
    evidence: "Local fallback/demo data",
  },
];

const statusClasses: Record<SupplyChainEvidence["status"], string> = {
  allowed: "border-emerald-200 bg-emerald-100 text-emerald-800",
  blocked: "border-red-200 bg-red-100 text-red-800",
  passing: "border-blue-200 bg-blue-100 text-blue-800",
  warning: "border-amber-200 bg-amber-100 text-amber-800",
};

export function SupplyChainPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        icon={PackageCheck}
        title="Supply Chain Status"
        description="Cosign, Kyverno verifyImages, and Trivy controls for image provenance and vulnerability posture."
      />

      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
        Supply-chain status is shown from clearly marked local fallback/demo data because no frontend REST
        endpoint exists for Cosign, Kyverno verifyImages, or Trivy results yet.
      </div>

      <SectionCard title="Image Admission Evidence" icon={ShieldCheck} contentClassName="space-y-3">
        {fallbackSupplyChainEvidence.map((item) => (
          <div
            key={item.name}
            className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 lg:grid-cols-[1fr_auto]"
          >
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-950">{item.name}</h3>
                <Badge className={`border ${statusClasses[item.status]}`}>{item.status}</Badge>
                <Badge className="border border-amber-200 bg-amber-100 text-amber-800">{item.evidence}</Badge>
              </div>
              <p className="mt-2 text-sm text-slate-600">{item.detail}</p>
            </div>
          </div>
        ))}
      </SectionCard>
    </div>
  );
}

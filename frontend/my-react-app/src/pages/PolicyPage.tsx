import { Ban, CheckCircle2, ShieldCheck } from "lucide-react";

import { SectionCard } from "@/components/common/SectionCard";
import { PageHeader } from "@/components/layout/PageHeader";
import { Badge } from "@/components/ui/badge";

type PolicyEvidence = {
  blocked: number;
  description: string;
  evidence: string;
  name: string;
  rule: string;
};

const fallbackPolicyEvidence: PolicyEvidence[] = [
  {
    name: "Privileged containers blocked",
    rule: "disallow-privileged-containers",
    blocked: 4,
    evidence: "Local fallback/demo data",
    description: "Pods requesting privileged=true are denied before admission.",
  },
  {
    name: "hostPath blocked",
    rule: "disallow-host-path",
    blocked: 3,
    evidence: "Local fallback/demo data",
    description: "Workloads attempting host filesystem mounts are blocked.",
  },
  {
    name: "Missing resources blocked",
    rule: "require-requests-limits",
    blocked: 7,
    evidence: "Local fallback/demo data",
    description: "Containers missing CPU or memory requests and limits are rejected.",
  },
  {
    name: "Registry violations blocked",
    rule: "allowed-image-registries",
    blocked: 2,
    evidence: "Local fallback/demo data",
    description: "Images from unapproved registries are denied.",
  },
  {
    name: "Unsigned image blocked by verifyImages",
    rule: "verify-image-signatures",
    blocked: 5,
    evidence: "Local fallback/demo data",
    description: "Unsigned images fail Kyverno verifyImages enforcement.",
  },
];

export function PolicyPage() {
  const blockedTotal = fallbackPolicyEvidence.reduce((total, item) => total + item.blocked, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ShieldCheck}
        title="Policy Enforcement"
        description="Kyverno policy posture for admission-time workload controls."
      />

      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
        Kyverno evidence is shown from clearly marked local fallback/demo data because no frontend REST endpoint
        exists for policy-admission events yet.
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="text-sm text-slate-500">Total Blocks</div>
          <div className="mt-2 text-3xl font-semibold text-slate-950">{blockedTotal}</div>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="text-sm text-slate-500">Enforcement Mode</div>
          <div className="mt-2 flex items-center gap-2 text-lg font-semibold text-slate-950">
            <CheckCircle2 className="h-5 w-5 text-emerald-600" />
            Enforce
          </div>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="text-sm text-slate-500">Signal Source</div>
          <div className="mt-2 text-lg font-semibold text-slate-950">Kyverno</div>
        </div>
      </div>

      <SectionCard title="Blocked Policy Evidence" icon={Ban} contentClassName="space-y-3">
        {fallbackPolicyEvidence.map((item) => (
          <div
            key={item.rule}
            className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 lg:grid-cols-[1fr_auto]"
          >
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-950">{item.name}</h3>
                <Badge variant="outline" className="rounded-full">{item.rule}</Badge>
                <Badge className="border border-amber-200 bg-amber-100 text-amber-800">{item.evidence}</Badge>
              </div>
              <p className="mt-2 text-sm text-slate-600">{item.description}</p>
            </div>
            <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-center">
              <div className="text-2xl font-semibold text-slate-950">{item.blocked}</div>
              <div className="text-xs uppercase tracking-wide text-slate-500">blocked</div>
            </div>
          </div>
        ))}
      </SectionCard>
    </div>
  );
}

import { Gauge } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { ChartCard } from "@/components/charts/ChartCard";
import type { PodRiskDatum } from "@/utils/analytics";

type TopPodsRiskChartProps = {
  data: PodRiskDatum[];
};

export function TopPodsRiskChart({ data }: TopPodsRiskChartProps) {
  return (
    <ChartCard title="Top Risky Pods" icon={Gauge} hasData={data.length > 0}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 8, right: 12, left: 16, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
          <XAxis type="number" tick={{ fontSize: 12 }} />
          <YAxis type="category" dataKey="pod" width={110} tick={{ fontSize: 11 }} />
          <Tooltip />
          <Bar dataKey="risk" fill="#7c3aed" radius={[0, 6, 6, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

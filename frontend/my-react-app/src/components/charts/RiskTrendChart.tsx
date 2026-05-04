import { TrendingUp } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { ChartCard } from "@/components/charts/ChartCard";
import type { RiskTrendDatum } from "@/utils/analytics";

type RiskTrendChartProps = {
  data: RiskTrendDatum[];
};

export function RiskTrendChart({ data }: RiskTrendChartProps) {
  return (
    <ChartCard title="Risk Trend" icon={TrendingUp} hasData={data.length > 0}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
          <XAxis dataKey="label" tick={{ fontSize: 12 }} />
          <YAxis domain={[0, "auto"]} tick={{ fontSize: 12 }} />
          <Tooltip />
          <Line type="monotone" dataKey="risk" stroke="#2563eb" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

import { Activity } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { ChartCard } from "@/components/charts/ChartCard";
import type { TypeChartDatum } from "@/utils/analytics";

type EventsByTypeChartProps = {
  data: TypeChartDatum[];
};

export function EventsByTypeChart({ data }: EventsByTypeChartProps) {
  return (
    <ChartCard title="Events By Type" icon={Activity} hasData={data.length > 0}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 8, right: 12, left: 16, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
          <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12 }} />
          <YAxis type="category" dataKey="type" width={110} tick={{ fontSize: 11 }} />
          <Tooltip />
          <Bar dataKey="count" fill="#0f766e" radius={[0, 6, 6, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

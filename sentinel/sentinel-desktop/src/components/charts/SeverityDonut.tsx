// SeverityDonut — frosted-glass donut for finding severity breakdown.
// Implemented by Agent UI-10.

import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

export interface SeverityDonutProps {
  critical: number;
  high: number;
  medium: number;
  info?: number;
  size?: number;
}

const COLORS = {
  critical: '#ff453a', // sentinel-red
  high: '#ff9f0a', // sentinel-orange
  medium: '#0a84ff', // sentinel-blue
  info: '#34c759', // sentinel-green
};

export default function SeverityDonut({
  critical,
  high,
  medium,
  info = 0,
  size = 160,
}: SeverityDonutProps) {
  const total = critical + high + medium + info;

  const data =
    total === 0
      ? [{ name: 'empty', value: 1, color: 'rgba(255,255,255,0.06)' }]
      : [
          { name: 'Critical', value: critical, color: COLORS.critical },
          { name: 'High', value: high, color: COLORS.high },
          { name: 'Medium', value: medium, color: COLORS.medium },
          { name: 'Info', value: info, color: COLORS.info },
        ].filter((d) => d.value > 0);

  const outerRadius = size / 2;
  const innerRadius = Math.round(outerRadius * 0.66);

  return (
    <div
      className="relative"
      style={{ width: size, height: size }}
      aria-label={`${total} findings`}
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={innerRadius}
            outerRadius={outerRadius}
            paddingAngle={total === 0 ? 0 : 2}
            stroke="rgba(255,255,255,0.14)"
            strokeWidth={1}
            isAnimationActive={false}
          >
            {data.map((d) => (
              <Cell key={d.name} fill={d.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>

      {/* Center label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="text-[24px] font-semibold text-sentinel-text-primary leading-none">
          {total}
        </div>
        <div className="section-heading mt-1.5">findings</div>
      </div>
    </div>
  );
}

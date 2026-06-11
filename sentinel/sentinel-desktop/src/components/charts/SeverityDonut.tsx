// SeverityDonut — calm-surface donut for finding severity breakdown.
// Implemented by Agent UI-10.

import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

export interface SeverityDonutProps {
  critical: number;
  high: number;
  medium: number;
  info?: number;
  size?: number;
}

// Canonical severity mapping (design system): critical / high / medium / info.
const COLORS = {
  critical: '#e5534b', // sentinel-critical
  high: '#e8804f', // sentinel-high
  medium: '#d9a83c', // sentinel-medium
  info: '#8ea3c0', // sentinel-info
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
      ? [{ name: 'empty', value: 1, color: 'rgba(255,255,255,0.05)' }]
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
      role="img"
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
            stroke="rgba(255,255,255,0.08)"
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
        <div className="text-metric-lg tabular-nums text-sentinel-text-primary">
          {total}
        </div>
        <div className="section-heading mt-1">findings</div>
      </div>
    </div>
  );
}

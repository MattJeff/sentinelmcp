// Sparkline — tiny area chart with token-colored gradient glow.
// Implemented by Agent UI-10.

import { useId } from 'react';
import { AreaChart, Area, ResponsiveContainer, YAxis } from 'recharts';

export type SparklineColor = 'green' | 'orange' | 'red' | 'blue';

export interface SparklineProps {
  values: number[];
  color?: SparklineColor;
  height?: number;
  width?: number;
}

const COLOR_MAP: Record<SparklineColor, string> = {
  green: '#34c759',
  orange: '#ff9f0a',
  red: '#ff453a',
  blue: '#0a84ff',
};

export default function Sparkline({
  values,
  color = 'blue',
  width = 120,
  height = 36,
}: SparklineProps) {
  const gradientId = `sparkline-${useId().replace(/[:]/g, '')}`;
  const stroke = COLOR_MAP[color];

  const data = values.map((v, i) => ({ i, v }));

  // Padding so the line doesn't graze the edges
  const min = values.length ? Math.min(...values) : 0;
  const max = values.length ? Math.max(...values) : 1;
  const padding = (max - min) * 0.15 || 1;

  return (
    <div style={{ width, height }} aria-hidden>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 2, right: 2, bottom: 2, left: 2 }}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={stroke} stopOpacity={0.55} />
              <stop offset="100%" stopColor={stroke} stopOpacity={0} />
            </linearGradient>
          </defs>
          <YAxis hide domain={[min - padding, max + padding]} />
          <Area
            type="monotone"
            dataKey="v"
            stroke={stroke}
            strokeWidth={1.5}
            fill={`url(#${gradientId})`}
            isAnimationActive={false}
            dot={false}
            activeDot={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

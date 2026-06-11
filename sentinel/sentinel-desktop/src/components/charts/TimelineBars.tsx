// TimelineBars — stacked severity bars over time on a calm surface.
// Implemented by Agent UI-10.

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';

export interface TimelinePoint {
  date: string; // ISO-8601 or display string
  critical: number;
  high: number;
  medium: number;
}

export interface TimelineBarsProps {
  points: TimelinePoint[];
  height?: number;
}

// Canonical severity mapping (design system).
const COLORS = {
  critical: '#e5534b', // sentinel-critical
  high: '#e8804f', // sentinel-high
  medium: '#d9a83c', // sentinel-medium
};

const TICK_COLOR = 'rgba(245, 247, 251, 0.45)';

function formatShortDate(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const month = d.toLocaleString('en-US', { month: 'short' });
  return `${month} ${d.getDate()}`;
}

interface TooltipPayload {
  name: string;
  value: number;
  color: string;
  dataKey: string;
}

function GlassTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayload[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const total = payload.reduce((sum, p) => sum + (p.value ?? 0), 0);
  return (
    <div className="surface-raised rounded-lg px-3 py-2 text-caption shadow-raised">
      <div className="section-heading mb-2">
        {label ? formatShortDate(label) : ''}
      </div>
      <div className="flex flex-col gap-1">
        {payload
          .slice()
          .reverse()
          .map((p) => (
            <div
              key={p.dataKey}
              className="flex items-center gap-2 text-sentinel-text-secondary"
            >
              <span
                className="inline-block h-2 w-2 rounded-full"
                style={{ background: p.color }}
                aria-hidden
              />
              <span className="capitalize">{p.name}</span>
              <span className="ml-auto tabular-nums text-sentinel-text-primary">
                {p.value}
              </span>
            </div>
          ))}
        <div className="mt-2 pt-2 border-t border-sentinel-border-soft flex items-center gap-2 text-sentinel-text-tertiary">
          <span>Total</span>
          <span className="ml-auto tabular-nums text-sentinel-text-primary">
            {total}
          </span>
        </div>
      </div>
    </div>
  );
}

export default function TimelineBars({
  points,
  height = 200,
}: TimelineBarsProps) {
  return (
    <div style={{ width: '100%', height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={points}
          margin={{ top: 8, right: 8, left: -8, bottom: 0 }}
          barCategoryGap="22%"
        >
          <CartesianGrid
            stroke="rgba(255,255,255,0.05)"
            strokeDasharray="2 4"
            vertical={false}
          />
          <XAxis
            dataKey="date"
            tickFormatter={formatShortDate}
            axisLine={false}
            tickLine={false}
            tick={{ fill: TICK_COLOR, fontSize: 11 }}
            dy={4}
          />
          <YAxis
            allowDecimals={false}
            axisLine={false}
            tickLine={false}
            tick={{ fill: TICK_COLOR, fontSize: 11 }}
            width={32}
          />
          <Tooltip
            cursor={{ fill: 'rgba(255,255,255,0.03)' }}
            content={<GlassTooltip />}
          />
          <Bar
            dataKey="medium"
            name="Medium"
            stackId="sev"
            fill={COLORS.medium}
            radius={[0, 0, 0, 0]}
            isAnimationActive={false}
          />
          <Bar
            dataKey="high"
            name="High"
            stackId="sev"
            fill={COLORS.high}
            radius={[0, 0, 0, 0]}
            isAnimationActive={false}
          />
          <Bar
            dataKey="critical"
            name="Critical"
            stackId="sev"
            fill={COLORS.critical}
            radius={[2, 2, 0, 0]}
            isAnimationActive={false}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

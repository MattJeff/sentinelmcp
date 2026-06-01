// MetricCard — glass card with a label, value, optional trend + sparkline.
// Implemented by Agent UI-10.

import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';
import clsx from 'clsx';

import Sparkline, { type SparklineColor } from './Sparkline';

export type MetricTone = 'green' | 'orange' | 'red' | 'blue' | 'neutral';

export interface MetricCardProps {
  label: string;
  value: string | number;
  trend?: 'up' | 'down' | 'flat';
  deltaLabel?: string;
  tone?: MetricTone;
  sparkline?: number[];
}

const ACCENT: Record<MetricTone, string> = {
  green:
    'linear-gradient(90deg, transparent, rgba(52,199,89,0.85), transparent)',
  orange:
    'linear-gradient(90deg, transparent, rgba(255,159,10,0.85), transparent)',
  red:
    'linear-gradient(90deg, transparent, rgba(255,69,58,0.90), transparent)',
  blue:
    'linear-gradient(90deg, transparent, rgba(10,132,255,0.85), transparent)',
  neutral:
    'linear-gradient(90deg, transparent, rgba(255,255,255,0.30), transparent)',
};

const TONE_TEXT: Record<MetricTone, string> = {
  green: 'text-sentinel-green-glow',
  orange: 'text-sentinel-orange-glow',
  red: 'text-sentinel-red-glow',
  blue: 'text-sentinel-blue-glow',
  neutral: 'text-sentinel-text-secondary',
};

const TREND_TONE: Record<'up' | 'down' | 'flat', string> = {
  up: 'text-sentinel-green-glow',
  down: 'text-sentinel-red-glow',
  flat: 'text-sentinel-text-tertiary',
};

const SPARK_COLOR: Record<MetricTone, SparklineColor> = {
  green: 'green',
  orange: 'orange',
  red: 'red',
  blue: 'blue',
  neutral: 'blue',
};

export default function MetricCard({
  label,
  value,
  trend,
  deltaLabel,
  tone = 'neutral',
  sparkline,
}: MetricCardProps) {
  const TrendIcon =
    trend === 'up' ? ArrowUpRight : trend === 'down' ? ArrowDownRight : Minus;

  return (
    <div className="card relative overflow-hidden">
      {/* Top accent bar (1 px gradient) */}
      <div
        className="absolute inset-x-0 top-0 h-px pointer-events-none"
        style={{ background: ACCENT[tone] }}
        aria-hidden
      />

      <div className="flex items-start justify-between gap-3">
        <div className="section-heading">{label}</div>
        {trend && (
          <div
            className={clsx(
              'inline-flex items-center gap-1 text-[11px] font-medium',
              TREND_TONE[trend],
            )}
          >
            <TrendIcon className="h-3.5 w-3.5" aria-hidden />
            {deltaLabel && <span>{deltaLabel}</span>}
          </div>
        )}
      </div>

      <div
        className={clsx(
          'mt-2 text-[28px] font-semibold leading-none tracking-tight',
          tone === 'neutral'
            ? 'text-sentinel-text-primary'
            : TONE_TEXT[tone],
        )}
      >
        {value}
      </div>

      {sparkline && sparkline.length > 1 && (
        <div className="mt-4 -mb-1">
          <Sparkline
            values={sparkline}
            color={SPARK_COLOR[tone]}
            width={220}
            height={40}
          />
        </div>
      )}
    </div>
  );
}

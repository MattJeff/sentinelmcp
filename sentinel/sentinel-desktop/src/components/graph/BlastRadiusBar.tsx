// BlastRadiusBar — horizontal frosted bar with a green→orange→red gradient
// fill proportional to score / max. The numeric score is shown on the right.
//
// Built by agent U2 for the Trust Graph view.

import clsx from 'clsx';

export interface BlastRadiusBarProps {
  score: number;
  max: number;
  label?: string;
  emphasised?: boolean;
  className?: string;
}

export default function BlastRadiusBar({
  score,
  max,
  label,
  emphasised,
  className,
}: BlastRadiusBarProps) {
  const safeMax = max > 0 ? max : 1;
  const ratio = Math.max(0, Math.min(1, score / safeMax));
  const pct = `${(ratio * 100).toFixed(1)}%`;

  // Tone for the numeric score text — mirrors the gradient at the bar's tip.
  const tone =
    ratio >= 0.75
      ? 'text-sentinel-red-glow'
      : ratio >= 0.4
        ? 'text-sentinel-orange-glow'
        : 'text-sentinel-green-glow';

  return (
    <div
      className={clsx(
        'glass-soft rounded-lg px-3 py-2 flex flex-col gap-1.5',
        emphasised && 'shadow-glow-red',
        className,
      )}
    >
      {label && (
        <div className="flex items-center justify-between gap-2">
          <div className="text-[12px] font-medium text-sentinel-text-primary truncate">
            {label}
          </div>
          <div className={clsx('text-[12px] font-mono tabular-nums', tone)}>
            {score.toFixed(0)}
            <span className="text-sentinel-text-tertiary"> / {max.toFixed(0)}</span>
          </div>
        </div>
      )}
      <div className="relative h-2 w-full overflow-hidden rounded-full bg-white/6">
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-[width] duration-300 ease-out"
          style={{
            width: pct,
            backgroundImage:
              'linear-gradient(90deg, #34c759 0%, #ffb340 55%, #ff453a 100%)',
            backgroundSize: `${100 / Math.max(ratio, 0.0001)}% 100%`,
            backgroundPosition: 'left center',
            boxShadow: emphasised ? '0 0 14px rgba(255,69,58,0.45)' : undefined,
          }}
        />
      </div>
      {!label && (
        <div className="flex items-center justify-end">
          <div className={clsx('text-[11px] font-mono tabular-nums', tone)}>
            {score.toFixed(0)}
          </div>
        </div>
      )}
    </div>
  );
}

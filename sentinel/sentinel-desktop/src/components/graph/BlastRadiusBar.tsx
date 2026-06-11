// BlastRadiusBar — horizontal bar with a flat severity-toned fill (ok / high /
// critical) proportional to score / max. The numeric score is shown on the right.
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

  // Severity tone — text token + flat fill colour, mapped on the canonical
  // scale (critical / high / ok).
  const tone =
    ratio >= 0.75
      ? 'text-sentinel-critical'
      : ratio >= 0.4
        ? 'text-sentinel-high'
        : 'text-sentinel-ok';
  const fill =
    ratio >= 0.75 ? '#e5534b' : ratio >= 0.4 ? '#e8804f' : '#4cc38a';

  return (
    <div
      className={clsx(
        'glass-soft rounded-lg px-3 py-2 flex flex-col gap-2 transition-colors duration-150 hover:bg-sentinel-raised hover:border-sentinel-border-strong',
        emphasised && 'border-sentinel-critical-border',
        className,
      )}
    >
      {label && (
        <div className="flex items-center justify-between gap-2">
          <div className="text-caption font-medium text-sentinel-text-primary truncate">
            {label}
          </div>
          <div className={clsx('text-caption font-medium tabular-nums', tone)}>
            {score.toFixed(0)}
            <span className="font-normal text-sentinel-text-tertiary"> / {max.toFixed(0)}</span>
          </div>
        </div>
      )}
      <div className="relative h-1.5 w-full overflow-hidden rounded-pill bg-white/6">
        <div
          className="absolute inset-y-0 left-0 rounded-pill transition-[width] duration-300 ease-out"
          style={{
            width: pct,
            backgroundColor: fill,
          }}
        />
      </div>
      {!label && (
        <div className="flex items-center justify-end">
          <div className={clsx('text-caption tabular-nums', tone)}>
            {score.toFixed(0)}
          </div>
        </div>
      )}
    </div>
  );
}

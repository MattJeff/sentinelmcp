// Overview > Hero — KPI tiles row.
// Pure presentational. Values are derived upstream from the discovery sweep,
// the findings store and the scan-progress tick.

import clsx from 'clsx';

interface HeroProps {
  /** `null` while data is loading or unavailable. `0` is a real value. */
  serversDetected: number | null;
  atRisk: number | null;
  critical: number | null;
  /** `null` when no scan has produced a red yet. */
  timeToFirstRedMs: number | null;
  isLoading: boolean;
}

const EMPTY_HINT = 'Run a scan from Discovery to populate';

export default function Hero({
  serversDetected,
  atRisk,
  critical,
  timeToFirstRedMs,
  isLoading,
}: HeroProps) {
  const atRiskGlow = (atRisk ?? 0) > 0;

  return (
    <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
      <KpiTile
        label="Servers detected"
        value={isLoading ? null : serversDetected}
        accent={<span className="dot dot-green" />}
      />
      <KpiTile
        label="At risk"
        value={isLoading ? null : atRisk}
        accent={
          <span
            className={clsx('dot dot-red', atRiskGlow && 'animate-pulse-glow')}
          />
        }
        emphasised={atRiskGlow}
      />
      <KpiTile
        label="Critical findings"
        value={isLoading ? null : critical}
        accent={
          <span className="pill pill-red text-[9px] px-1.5 py-0.5">Critical</span>
        }
      />
      <KpiTile
        label="Time to first red"
        value={
          isLoading
            ? null
            : timeToFirstRedMs === null
              ? '—'
              : `${timeToFirstRedMs} ms`
        }
        accent={<span className="section-heading">ms</span>}
        // ttfr null is a normal state, not "empty" — hide the hint there.
        suppressEmptyHint={timeToFirstRedMs === null}
      />
    </div>
  );
}

interface KpiTileProps {
  label: string;
  /** `null` → loading skeleton. Otherwise rendered as-is. */
  value: number | string | null;
  accent: React.ReactNode;
  emphasised?: boolean;
  /** When true, hide the "Run a scan…" hint even if value is empty. */
  suppressEmptyHint?: boolean;
}

function KpiTile({
  label,
  value,
  accent,
  emphasised,
  suppressEmptyHint,
}: KpiTileProps) {
  // Treat 0 / null / undefined as "empty" for hint purposes — but only show
  // the hint when the tile is settled (not in the skeleton loading state).
  const isEmpty =
    value === 0 || value === null || value === undefined || value === '—';
  const displayValue =
    value === null || value === undefined ? '—' : value;

  return (
    <div
      className={clsx(
        'card flex flex-col gap-3 min-w-0',
        emphasised && 'shadow-glow-red',
      )}
    >
      <div className="flex items-center justify-between gap-2 min-w-0">
        <div className="section-heading truncate">{label}</div>
        <div className="shrink-0">{accent}</div>
      </div>
      {value === null ? (
        <div className="skeleton h-8 w-20" />
      ) : (
        <div className="text-[28px] font-semibold leading-none tracking-tight text-sentinel-text-primary truncate">
          {displayValue}
        </div>
      )}
      {value !== null && isEmpty && !suppressEmptyHint && (
        <div className="text-[11px] text-sentinel-text-tertiary">
          {EMPTY_HINT}
        </div>
      )}
    </div>
  );
}

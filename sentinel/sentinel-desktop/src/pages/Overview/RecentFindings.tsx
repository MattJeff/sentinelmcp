// Overview > RecentFindings — last 5 findings list.

import clsx from 'clsx';
import type { Finding, Severity } from '../../api/contract';

interface RecentFindingsProps {
  findings: Finding[] | undefined;
  serverEndpointById?: Record<string, string>;
  isLoading: boolean;
}

const SEVERITY_PILL: Record<Severity, string> = {
  info: 'pill-blue',
  medium: 'pill-orange',
  high: 'pill-orange',
  critical: 'pill-red',
};

export default function RecentFindings({
  findings,
  serverEndpointById,
  isLoading,
}: RecentFindingsProps) {
  if (isLoading) {
    return (
      <div className="flex flex-col gap-3">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="skeleton h-12 w-full" />
        ))}
      </div>
    );
  }

  const items = (findings ?? []).slice(0, 5);

  if (items.length === 0) {
    return (
      <div className="text-sentinel-text-tertiary text-[13px] py-6">
        No findings yet — everything looks calm.
      </div>
    );
  }

  return (
    <ul className="flex flex-col">
      {items.map((f, idx) => {
        const endpoint = serverEndpointById?.[f.server_id] ?? f.server_id;
        return (
          <li
            key={f.id}
            className={clsx(
              'flex items-center gap-3 py-3',
              idx !== items.length - 1 && 'border-b border-white/5',
            )}
          >
            <span className={clsx('pill', SEVERITY_PILL[f.severity])}>
              {f.severity}
            </span>
            <div className="flex-1 min-w-0">
              <div className="text-[13px] font-medium text-sentinel-text-primary truncate">
                {f.title}
              </div>
              <div className="font-mono text-[11px] text-sentinel-text-tertiary truncate">
                {endpoint}
              </div>
            </div>
            <div className="text-[11px] text-sentinel-text-tertiary shrink-0 tabular-nums">
              {formatAppleDate(f.timestamp)}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

const MONTHS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];

function formatAppleDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const month = MONTHS[d.getMonth()];
  const day = d.getDate();
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${month} ${day}, ${hh}:${mm}`;
}

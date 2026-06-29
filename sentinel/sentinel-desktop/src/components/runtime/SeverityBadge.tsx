// SeverityBadge — single source of truth for severity → design-token mapping
// across the Runtime defenses panels (gate / sockets / CVE). Mirrors the
// canonical `.badge-*` classes in styles.css so severity colour only ever
// appears on a badge, never on a full surface.

import clsx from 'clsx';

export type SeverityLike =
  | 'info'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'
  | string;

/** Canonical `.badge-*` class for a (loosely-typed) severity string. */
export function severityBadgeClass(severity: SeverityLike): string {
  switch (severity) {
    case 'critical':
      return 'badge badge-critical';
    case 'high':
      return 'badge badge-high';
    case 'medium':
      return 'badge badge-medium';
    case 'info':
      return 'badge badge-info';
    default:
      // `low` and any unknown value fall back to the calm neutral pill.
      return 'badge badge-neutral';
  }
}

/** Status-dot class matching the same severity scale. */
export function severityDotClass(severity: SeverityLike): string {
  switch (severity) {
    case 'critical':
      return 'dot dot-critical';
    case 'high':
      return 'dot dot-high';
    case 'medium':
      return 'dot dot-medium';
    case 'info':
      return 'dot dot-info';
    default:
      return 'dot dot-accent';
  }
}

/** Numeric rank (high → low) so panels can sort most-severe first. */
export function severityRank(severity: SeverityLike): number {
  switch (severity) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    case 'info':
      return 1;
    default:
      return 0;
  }
}

interface SeverityBadgeProps {
  severity: SeverityLike;
  /** Override the displayed text (defaults to the severity itself). */
  label?: string;
  className?: string;
}

/** Small severity pill used across the Runtime panels. */
export default function SeverityBadge({
  severity,
  label,
  className,
}: SeverityBadgeProps) {
  return (
    <span className={clsx(severityBadgeClass(severity), className)}>
      {label ?? severity}
    </span>
  );
}

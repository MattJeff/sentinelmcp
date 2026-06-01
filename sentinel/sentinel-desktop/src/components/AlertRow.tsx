// AlertRow — one frosted row per Alert in the live feed.
// Click chevron to expand and reveal the DiffViewer.
// Implemented by Agent UI-4 for the Alerts page.

import { useEffect, useRef, useState } from 'react';
import { ChevronDown, MoreVertical, CheckCircle2 } from 'lucide-react';
import clsx from 'clsx';

import type { Alert, Severity } from '../api/contract';
import DiffViewer from './DiffViewer';

export interface AlertRowProps {
  alert: Alert;
  /** Optional handler — called when the user picks "Mark as resolved". */
  onResolve?: (alert: Alert) => void;
}

const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'dot-red',
  high: 'dot-red',
  medium: 'dot-orange',
  info: 'dot-green',
};

const SEVERITY_PILL: Record<Severity, string> = {
  critical: 'pill-red',
  high: 'pill-red',
  medium: 'pill-orange',
  info: 'pill-green',
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  info: 'Info',
};

export default function AlertRow({ alert, onResolve }: AlertRowProps) {
  const [open, setOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const isCritical = alert.severity === 'critical';

  // Close the menu when clicking outside.
  useEffect(() => {
    if (!menuOpen) return;
    const handler = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) setMenuOpen(false);
    };
    window.addEventListener('mousedown', handler);
    return () => window.removeEventListener('mousedown', handler);
  }, [menuOpen]);

  return (
    <div
      className={clsx(
        'glass-soft rounded-glass p-4 animate-fade-up',
        isCritical && 'shadow-glow-red',
      )}
    >
      {/* Narrow: stacked rows (severity → title/message → timestamp+actions).
          sm+: original single-row layout. */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3 w-full">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3 flex-1 min-w-0 text-left"
          aria-expanded={open}
        >
          {/* Row 1 (narrow) / left (wide): severity dot + pill */}
          <div className="flex items-center gap-2 shrink-0">
            <span className={clsx('dot', SEVERITY_DOT[alert.severity])} aria-hidden />
            <span className={clsx('pill', SEVERITY_PILL[alert.severity])}>
              {SEVERITY_LABEL[alert.severity]}
            </span>
          </div>

          {/* Row 2 (narrow) / center (wide): title + message */}
          <div className="flex-1 min-w-0">
            <div className="flex items-baseline gap-2 flex-wrap sm:flex-nowrap">
              <div className="text-[13px] font-semibold text-sentinel-text-primary truncate">
                {alert.title}
              </div>
              {/* Timestamp inline on sm+ only; on narrow it lives in the bottom row */}
              <div className="hidden sm:block text-[11px] text-sentinel-text-tertiary shrink-0">
                {formatAppleDate(alert.timestamp)}
              </div>
            </div>
            <div className="text-[12px] text-sentinel-text-secondary truncate mt-0.5">
              {alert.message}
            </div>
          </div>

          {/* Chevron (wide only — bottom row handles it on narrow) */}
          <ChevronDown
            className={clsx(
              'hidden sm:block h-4 w-4 shrink-0 text-sentinel-text-tertiary transition-transform duration-200',
              open && 'rotate-180',
            )}
          />
        </button>

        {/* Row 3 (narrow): timestamp + actions (chevron + kebab).
            sm+: just the kebab on the right. */}
        <div className="flex items-center justify-between gap-2 sm:gap-0 sm:justify-end sm:shrink-0">
          <div className="sm:hidden text-[11px] text-sentinel-text-tertiary">
            {formatAppleDate(alert.timestamp)}
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              aria-label={open ? 'Collapse alert' : 'Expand alert'}
              className="sm:hidden p-1 rounded-md text-sentinel-text-tertiary hover:text-white hover:bg-white/10 transition-colors"
            >
              <ChevronDown
                className={clsx(
                  'h-4 w-4 transition-transform duration-200',
                  open && 'rotate-180',
                )}
              />
            </button>

            {onResolve && (
              <div className="relative shrink-0" ref={menuRef}>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setMenuOpen((v) => !v);
                  }}
                  aria-label="Alert actions"
                  className="p-1 rounded-md text-sentinel-text-tertiary hover:text-white hover:bg-white/10 transition-colors"
                >
                  <MoreVertical className="h-4 w-4" />
                </button>
                {menuOpen && (
                  <div
                    role="menu"
                    className="absolute right-0 top-full mt-1 z-20 min-w-[200px] glass-soft rounded-glass p-1 shadow-glass-soft border border-white/10"
                  >
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        setMenuOpen(false);
                        onResolve(alert);
                      }}
                      className="flex items-center gap-2 w-full text-left rounded-md px-2.5 py-1.5 text-[12px] text-sentinel-text-primary hover:bg-white/10 transition-colors"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5 text-sentinel-text-secondary" />
                      Mark as resolved
                    </button>
                    <div className="px-2.5 pt-1 pb-1 text-[10px] text-sentinel-text-tertiary leading-tight">
                      Local only for now — backend resolve API not yet wired.
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {open && (
        <div className="mt-3 animate-fade-up">
          {alert.diff ? (
            // Wrap the diff so very wide code lines scroll horizontally
            // instead of stretching the row on narrow viewports.
            <div className="max-w-full overflow-x-auto">
              <DiffViewer diff={alert.diff} />
            </div>
          ) : (
            <div className="text-[12px] text-sentinel-text-tertiary px-1">
              No diff attached
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Apple-style short date: "Apr 12, 14:32"
function formatAppleDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const month = d.toLocaleString('en-US', { month: 'short' });
  const day = d.getDate();
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${month} ${day}, ${hh}:${mm}`;
}

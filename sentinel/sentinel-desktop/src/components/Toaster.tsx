// Toaster — frosted-glass toast stack, bottom-right.
// Subscribes to onAlert from @/api/tauri and surfaces incoming alerts.
// Implemented by Agent UI-12.
// Updated by Agent A1: count badge, pause-on-hover, working X button,
// stack cap at 5 visible, "Clear all" link when ≥ 3 active.

import { useEffect, useState } from 'react';
import { X, ChevronDown } from 'lucide-react';
import clsx from 'clsx';

import type { Severity } from '../api/contract';
import { onAlert, onScanProgress } from '../api/tauri';
import { useToastStore, type ToastItem } from '../hooks/useToast';
import DiffViewer from './DiffViewer';

const MAX_VISIBLE = 5;

const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'dot-critical',
  high: 'dot-high',
  medium: 'dot-medium',
  info: 'dot-info',
};

// Severity reads via a discreet 2px left edge — no glow halos.
const SEVERITY_EDGE: Record<Severity, string> = {
  critical: 'border-l-2 border-l-sentinel-critical',
  high: 'border-l-2 border-l-sentinel-high',
  medium: 'border-l-2 border-l-sentinel-medium',
  info: 'border-l-2 border-l-sentinel-info',
};

export default function Toaster() {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);
  const push = useToastStore((s) => s.push);
  const clear = useToastStore((s) => s.clear);
  const pause = useToastStore((s) => s.pause);
  const resume = useToastStore((s) => s.resume);

  // Wire backend alert stream → toast store. Lives once at root.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    onAlert((alert) => {
      push({
        title: alert.title,
        description: alert.message,
        severity: alert.severity,
        diff: alert.diff,
      });
    }).then((fn) => {
      if (cancelled) {
        fn();
      } else {
        unlisten = fn;
      }
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [push]);

  // Wire Live Scan progress → toast store. Probe "Probing X…" / "Probe failed
  // for X…" lines are aggregated silently and surfaced as a SINGLE summary
  // toast when the scan finishes. The Activity log inside the Live Scan page
  // still shows each line normally. Lines containing "poisoning" remain
  // critical (sticky) so true threats cannot be missed.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    // Probe counters are scoped to this effect; they reset whenever a new
    // scan starts (i.e. when we observe "probing" after a previous finish).
    const probed = new Set<string>();
    const failed = new Set<string>();
    let sawProbeActivity = false;

    const resetCounters = () => {
      probed.clear();
      failed.clear();
      sawProbeActivity = false;
    };

    const parseTarget = (line: string, marker: string): string | null => {
      const idx = line.toLowerCase().indexOf(marker);
      if (idx < 0) return null;
      const rest = line.slice(idx + marker.length).trim();
      // Strip trailing punctuation/ellipsis and anything after a colon.
      const colonIdx = rest.indexOf(':');
      const target = (colonIdx >= 0 ? rest.slice(0, colonIdx) : rest)
        .replace(/[…\.\s]+$/u, '')
        .trim();
      return target.length > 0 ? target : null;
    };

    onScanProgress((progress) => {
      const line = progress.log_line;
      if (!line) {
        // Stage-only event (e.g. finished without log_line): still emit summary.
        if (progress.stage === 'finished' && sawProbeActivity) {
          const n = probed.size;
          const m = failed.size;
          push({
            title: `Scan finished — ${n} servers probed, ${m} failed`,
            severity: m > 0 ? 'medium' : 'info',
          });
          resetCounters();
        }
        return;
      }
      const lower = line.toLowerCase();
      const isProbing = lower.includes('probing');
      const isProbeFailed = lower.includes('probe failed');
      const isFinished = lower.includes('finished') || progress.stage === 'finished';
      const isPoisoning = lower.includes('poisoning');

      if (isProbing) {
        const target = parseTarget(line, 'probing');
        if (target) probed.add(target);
        sawProbeActivity = true;
        return; // no toast per probe
      }

      if (isProbeFailed) {
        const target = parseTarget(line, 'probe failed for');
        if (target) {
          probed.add(target);
          failed.add(target);
        }
        sawProbeActivity = true;
        return; // no toast per failure
      }

      if (isPoisoning) {
        push({
          title: line,
          description: progress.servers_discovered
            ? `${progress.servers_discovered} servers · ${progress.tools_discovered} tools`
            : undefined,
          severity: 'critical',
        });
        return;
      }

      if (isFinished) {
        if (sawProbeActivity) {
          const n = probed.size;
          const m = failed.size;
          push({
            title: `Scan finished — ${n} servers probed, ${m} failed`,
            severity: m > 0 ? 'medium' : 'info',
          });
          resetCounters();
        } else {
          push({
            title: line,
            description: progress.servers_discovered
              ? `${progress.servers_discovered} servers · ${progress.tools_discovered} tools`
              : undefined,
            severity: 'info',
          });
        }
      }
      // Other routine lines ("discovered", etc.) are intentionally silent now;
      // they remain visible in the Live Scan Activity log.
    }).then((fn) => {
      if (cancelled) {
        fn();
      } else {
        unlisten = fn;
      }
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [push]);

  // Newest first; cap at 5 visible (rest queued).
  const ordered = [...toasts].reverse();
  const visible = ordered.slice(0, MAX_VISIBLE);
  const showClearAll = toasts.length >= 3;

  return (
    <div
      aria-live="polite"
      aria-atomic="false"
      className="pointer-events-none fixed bottom-6 right-6 z-[60] flex w-[360px] max-w-[calc(100vw-3rem)] flex-col gap-3"
    >
      {visible.map((t) => (
        <ToastCard
          key={t.id}
          toast={t}
          onClose={() => dismiss(t.id)}
          onMouseEnter={() => pause(t.id)}
          onMouseLeave={() => resume(t.id)}
        />
      ))}
      {showClearAll ? (
        <div className="pointer-events-auto flex justify-end">
          <button
            type="button"
            onClick={clear}
            className="text-caption font-medium text-sentinel-text-tertiary hover:text-sentinel-text-primary transition-colors duration-150 underline-offset-2 hover:underline focus-visible:outline-none focus-visible:shadow-focus rounded-lg"
          >
            Clear all
          </button>
        </div>
      ) : null}
    </div>
  );
}

interface ToastCardProps {
  toast: ToastItem;
  onClose: () => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}

function ToastCard({ toast, onClose, onMouseEnter, onMouseLeave }: ToastCardProps) {
  const [expanded, setExpanded] = useState(false);
  const edge = SEVERITY_EDGE[toast.severity];

  return (
    <div
      role={toast.severity === 'critical' ? 'alert' : 'status'}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      className={clsx(
        'surface-raised shadow-raised rounded-glass pointer-events-auto p-4 animate-fade-up relative',
        edge,
      )}
      style={{ animationName: 'fadeUp' }}
    >
      {toast.count > 1 ? (
        <span
          className="absolute top-2 right-9 inline-flex items-center justify-center rounded-pill bg-white/12 px-2 py-0.5 text-overline text-sentinel-text-primary tabular-nums"
          aria-label={`${toast.count} occurrences`}
        >
          × {toast.count}
        </span>
      ) : null}
      <div className="flex items-start gap-3">
        <span
          className={clsx('dot mt-1.5 shrink-0', SEVERITY_DOT[toast.severity])}
          aria-hidden
        />
        <div className="min-w-0 flex-1">
          <div className="text-body font-semibold text-sentinel-text-primary leading-tight">
            {toast.title}
          </div>
          {toast.description ? (
            <div className="mt-1 text-caption text-sentinel-text-secondary">
              {toast.description}
            </div>
          ) : null}
          {toast.diff ? (
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="mt-2 inline-flex items-center gap-1 rounded-lg text-caption font-medium text-sentinel-accent hover:text-sentinel-text-primary transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus"
              aria-expanded={expanded}
            >
              <ChevronDown
                className={clsx(
                  'h-3 w-3 transition-transform duration-200',
                  expanded && 'rotate-180',
                )}
                aria-hidden
              />
              {expanded ? 'Hide diff' : 'View diff'}
            </button>
          ) : null}
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Dismiss notification"
          className="shrink-0 rounded-lg p-1 text-sentinel-text-tertiary hover:text-sentinel-text-primary hover:bg-white/8 transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus"
        >
          <X className="h-3.5 w-3.5" aria-hidden />
        </button>
      </div>

      {expanded && toast.diff ? (
        <div className="mt-3 max-h-[176px] overflow-auto animate-fade-up">
          <DiffViewer diff={truncateDiff(toast.diff, 8)} />
        </div>
      ) : null}
    </div>
  );
}

// Keep the inline mini-diff visually contained — 8 lines max.
function truncateDiff(diff: string, maxLines: number): string {
  const lines = diff.split('\n');
  if (lines.length <= maxLines) return diff;
  return [...lines.slice(0, maxLines), `… ${lines.length - maxLines} more lines`].join('\n');
}

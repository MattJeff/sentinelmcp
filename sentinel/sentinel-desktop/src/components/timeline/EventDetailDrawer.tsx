// EventDetailDrawer — frosted-glass right-side drawer that shows the full
// JSON-RPC envelope of an observed event. Reuses the visual pattern from
// ServerDetailDrawer (overlay + slide-in panel + escape-to-close).
// Implemented by Agent U3.

import { useEffect, useMemo, useState } from 'react';
import clsx from 'clsx';
import {
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  Check,
  Copy,
  X,
} from 'lucide-react';

import type { ObservedEvent } from '../../api/contract';

export interface EventDetailDrawerProps {
  event: ObservedEvent | null;
  onClose: () => void;
  onShowInInventory?: (serverId: string) => void;
}

// Same color taxonomy as EventRow — kept local so the two components stay
// independent and can be tweaked in isolation if needed.
function methodBadgeClass(method: string): string {
  if (method === 'initialize' || method === 'tools/list') return 'badge-accent';
  if (method === 'tools/call') return 'badge-medium';
  if (method.startsWith('notifications/')) return 'badge-ok';
  return 'badge-neutral';
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const month = d.toLocaleString('en-US', { month: 'short' });
  const day = d.getDate();
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${month} ${day}, ${hh}:${mm}:${ss}`;
}

// Returns a copy of the envelope where any `params.arguments` is replaced
// with the literal "<<redacted>>". Only applied when the method is
// `tools/call` — auditors must not see raw tool arguments by default.
function redactEnvelope(event: ObservedEvent): Record<string, unknown> {
  const cloned: Record<string, unknown> = JSON.parse(
    JSON.stringify(event.envelope ?? {}),
  );
  if (event.method !== 'tools/call') return cloned;

  const params = cloned['params'];
  if (params && typeof params === 'object') {
    const paramsObj = params as Record<string, unknown>;
    if ('arguments' in paramsObj) {
      paramsObj['arguments'] = '<<redacted>>';
    }
  }
  return cloned;
}

export default function EventDetailDrawer({
  event,
  onClose,
  onShowInInventory,
}: EventDetailDrawerProps) {
  const open = event !== null;

  // Close on Escape.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  // Lock body scroll while open.
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = window.setTimeout(() => setCopied(false), 1400);
    return () => window.clearTimeout(t);
  }, [copied]);

  const prettyJson = useMemo(() => {
    if (!event) return '';
    return JSON.stringify(redactEnvelope(event), null, 2);
  }, [event]);

  if (!open || !event) return null;

  const isClientToServer = event.direction === 'client_to_server';
  const directionLabel = isClientToServer
    ? 'Client → Server'
    : 'Server → Client';
  const DirectionIcon = isClientToServer ? ArrowRight : ArrowLeft;

  const badgeClass = methodBadgeClass(event.method);

  const handleCopy = async () => {
    // Prefer the async Clipboard API (works in Tauri's webview and in modern
    // browser secure contexts). Fall back to a synchronous textarea + the
    // legacy execCommand path so users on non-secure contexts (e.g. the
    // dev http://localhost shell on some platforms) still get a real copy.
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(prettyJson);
        setCopied(true);
        return;
      }
    } catch {
      // fall through to the legacy path
    }
    try {
      const ta = document.createElement('textarea');
      ta.value = prettyJson;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '0';
      ta.style.left = '0';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) setCopied(true);
    } catch {
      // Best-effort only — we don't have a toaster channel from this drawer.
    }
  };

  const handleShowInInventory = () => {
    onShowInInventory?.(event.server_id);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50"
      role="dialog"
      aria-modal="true"
      aria-label="Observed event detail"
    >
      {/* Dim + blur overlay */}
      <button
        type="button"
        aria-label="Close drawer"
        onClick={onClose}
        className="absolute inset-0 bg-black/50 backdrop-blur-xs animate-fade-up"
        style={{ animationDuration: '200ms' }}
      />

      {/* Panel — 520 px wide per spec */}
      <aside
        className="surface-raised absolute right-0 top-0 h-full w-[520px] max-w-full flex flex-col"
        style={{
          animation: 'drawerSlideIn 280ms cubic-bezier(0.2, 0, 0, 1) both',
        }}
      >
        <style>{`
          @keyframes drawerSlideIn {
            0% { transform: translateX(100%); opacity: 0; }
            100% { transform: translateX(0); opacity: 1; }
          }
        `}</style>

        {/* Header */}
        <header className="flex items-start gap-3 p-6 border-b border-sentinel-border-soft">
          <span
            className={clsx(
              'mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full',
              isClientToServer
                ? 'bg-sentinel-accent-dim text-sentinel-accent'
                : 'bg-sentinel-violet/14 text-sentinel-violet',
            )}
            aria-hidden
          >
            <DirectionIcon size={14} />
          </span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={clsx('badge', badgeClass)}>{event.method}</span>
              <span className="text-overline text-sentinel-text-tertiary">
                {directionLabel}
              </span>
            </div>
            <div className="mt-2 font-mono text-body text-sentinel-text-primary truncate">
              {event.server_endpoint}
            </div>
            <div className="mt-1 flex items-center gap-3 text-caption text-sentinel-text-tertiary font-mono tabular-nums">
              <span>{formatTimestamp(event.timestamp)}</span>
              {event.jsonrpc_id !== null &&
                event.jsonrpc_id !== undefined && (
                  <span>id {String(event.jsonrpc_id)}</span>
                )}
              <span>session {event.session_id}</span>
            </div>
          </div>
          <button
            type="button"
            className="btn no-drag !px-2 !py-2"
            onClick={onClose}
            aria-label="Close"
            title="Close"
          >
            <X size={16} />
          </button>
        </header>

        {/* Body — pretty-printed JSON envelope */}
        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4">
          <section className="card animate-fade-up">
            <div className="flex items-center justify-between mb-3">
              <div className="section-heading">JSON-RPC envelope</div>
              {event.method === 'tools/call' && (
                <span className="badge badge-medium">
                  arguments redacted
                </span>
              )}
            </div>
            <pre
              className={clsx(
                'bg-sentinel-inset border border-sentinel-border-soft rounded-lg',
                'p-4 font-mono text-caption leading-relaxed',
                'text-sentinel-text-secondary',
                'overflow-x-auto whitespace-pre',
              )}
            >
              {prettyJson}
            </pre>
          </section>
        </div>

        {/* Sticky footer — actions */}
        <footer className="glass-soft border-t border-sentinel-border p-4 flex items-center gap-2">
          <button
            type="button"
            className="btn btn-primary no-drag flex-1 justify-center"
            onClick={handleCopy}
          >
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy JSON'}
          </button>
          <button
            type="button"
            className="btn no-drag flex-1 justify-center"
            onClick={handleShowInInventory}
            disabled={!onShowInInventory}
          >
            <ArrowUpRight size={14} />
            Show in inventory
          </button>
        </footer>
      </aside>
    </div>
  );
}

// EventRow — one row of the Time-travel feed.
// Renders a captured JSON-RPC envelope as a glass-soft tile with timestamp,
// direction arrow, method pill (colored by category), server name and the
// optional JSON-RPC id. Click anywhere to open EventDetailDrawer.
// Implemented by Agent U3.

import clsx from 'clsx';
import { ArrowLeft, ArrowRight, ChevronRight } from 'lucide-react';

import type { ObservedEvent } from '../../api/contract';

export interface EventRowProps {
  event: ObservedEvent;
  onSelect: (event: ObservedEvent) => void;
}

// Color taxonomy from the brief:
//   initialize / tools/list → blue
//   tools/call              → orange
//   notifications/*         → green
//   everything else         → tertiary (neutral pill)
function methodPillClass(method: string): string {
  if (method === 'initialize' || method === 'tools/list') return 'pill-blue';
  if (method === 'tools/call') return 'pill-orange';
  if (method.startsWith('notifications/')) return 'pill-green';
  return 'pill-tertiary';
}

// Apple-style short date: "Apr 12, 14:32:08"
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

export default function EventRow({ event, onSelect }: EventRowProps) {
  const isClientToServer = event.direction === 'client_to_server';
  const Arrow = isClientToServer ? ArrowRight : ArrowLeft;
  const directionLabel = isClientToServer ? 'client to server' : 'server to client';
  const pillClass = methodPillClass(event.method);
  // Custom neutral pill for "everything else" — keep aligned with .pill geometry.
  const neutralPill =
    'inline-flex items-center gap-1 rounded-pill px-2 py-0.5 text-[10px] font-medium tracking-wide uppercase bg-white/6 text-sentinel-text-tertiary border border-white/10';

  return (
    <button
      type="button"
      onClick={() => onSelect(event)}
      className={clsx(
        'glass-soft rounded-glass w-full text-left min-w-0',
        'group relative flex flex-col md:flex-row md:items-center gap-2 md:gap-3 px-4 py-3',
        'transition-all duration-200',
        'hover:-translate-y-0.5 hover:bg-white/8 hover:shadow-glass-soft',
      )}
      aria-label={`Open detail for ${event.method} at ${formatTimestamp(event.timestamp)}`}
    >
      {/* Top row on mobile: timestamp + arrow + method pill */}
      <div className="flex items-center gap-3 md:contents min-w-0">
        {/* Timestamp */}
        <span className="font-mono text-[11px] text-sentinel-text-tertiary tabular-nums shrink-0 md:w-[140px]">
          {formatTimestamp(event.timestamp)}
        </span>

        {/* Direction arrow */}
        <span
          className={clsx(
            'flex h-6 w-6 shrink-0 items-center justify-center rounded-full',
            isClientToServer
              ? 'bg-sentinel-blue/12 text-sentinel-blue-glow'
              : 'bg-sentinel-purple/14 text-sentinel-purple',
          )}
          aria-label={directionLabel}
          title={directionLabel}
        >
          <Arrow size={13} />
        </span>

        {/* Method pill */}
        {pillClass === 'pill-tertiary' ? (
          <span className={clsx(neutralPill, 'shrink-0')}>{event.method}</span>
        ) : (
          <span className={clsx('pill shrink-0', pillClass)}>{event.method}</span>
        )}
      </div>

      {/* Bottom row on mobile: endpoint + id + chevron */}
      <div className="flex items-center gap-3 md:contents min-w-0 w-full">
        {/* Server endpoint */}
        <span className="font-mono text-[12px] text-sentinel-text-secondary truncate flex-1 min-w-0">
          {event.server_endpoint}
        </span>

        {/* JSON-RPC id (optional) */}
        {event.jsonrpc_id !== null && event.jsonrpc_id !== undefined && (
          <span className="font-mono text-[11px] text-sentinel-text-tertiary shrink-0">
            id {String(event.jsonrpc_id)}
          </span>
        )}

        {/* Hover hint + chevron */}
        <span className="hidden md:group-hover:inline-flex md:items-center text-[11px] text-sentinel-blue-glow shrink-0">
          View detail
        </span>
        <ChevronRight
          size={14}
          className="text-sentinel-text-tertiary shrink-0 transition-transform duration-200 group-hover:translate-x-0.5 group-hover:text-sentinel-text-secondary"
        />
      </div>
    </button>
  );
}

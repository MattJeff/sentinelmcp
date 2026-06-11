// EventRow — one row of the Time-travel feed.
// Renders a captured JSON-RPC envelope as a surface row with timestamp,
// direction arrow, method badge (colored by category), server name and the
// optional JSON-RPC id. Click anywhere to open EventDetailDrawer.
// Implemented by Agent U3.

import clsx from 'clsx';
import { ArrowLeft, ArrowRight, ChevronRight } from 'lucide-react';

import type { ObservedEvent } from '../../api/contract';

export interface EventRowProps {
  event: ObservedEvent;
  onSelect: (event: ObservedEvent) => void;
}

// Color taxonomy from the brief, mapped to semantic badge tokens:
//   initialize / tools/list → accent
//   tools/call              → medium
//   notifications/*         → ok
//   everything else         → neutral
function methodBadgeClass(method: string): string {
  if (method === 'initialize' || method === 'tools/list') return 'badge-accent';
  if (method === 'tools/call') return 'badge-medium';
  if (method.startsWith('notifications/')) return 'badge-ok';
  return 'badge-neutral';
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
  const badgeClass = methodBadgeClass(event.method);

  return (
    <button
      type="button"
      onClick={() => onSelect(event)}
      className={clsx(
        'surface rounded-glass w-full text-left min-w-0',
        'group relative flex flex-col md:flex-row md:items-center gap-3 px-4 py-3',
        'transition-colors duration-150',
        'hover:bg-sentinel-raised hover:border-sentinel-border-strong',
        'focus-visible:outline-none focus-visible:shadow-focus',
      )}
      aria-label={`Open detail for ${event.method} at ${formatTimestamp(event.timestamp)}`}
    >
      {/* Top row on mobile: timestamp + arrow + method badge */}
      <div className="flex items-center gap-3 md:contents min-w-0">
        {/* Timestamp */}
        <span className="font-mono text-caption text-sentinel-text-tertiary tabular-nums shrink-0 md:w-[140px]">
          {formatTimestamp(event.timestamp)}
        </span>

        {/* Direction arrow */}
        <span
          className={clsx(
            'flex h-6 w-6 shrink-0 items-center justify-center rounded-full',
            isClientToServer
              ? 'bg-sentinel-accent-dim text-sentinel-accent'
              : 'bg-sentinel-violet/14 text-sentinel-violet',
          )}
          aria-label={directionLabel}
          title={directionLabel}
        >
          <Arrow size={13} />
        </span>

        {/* Method badge */}
        <span className={clsx('badge shrink-0', badgeClass)}>
          {event.method}
        </span>
      </div>

      {/* Bottom row on mobile: endpoint + id + chevron */}
      <div className="flex items-center gap-3 md:contents min-w-0 w-full">
        {/* Server endpoint */}
        <span className="font-mono text-caption text-sentinel-text-secondary truncate flex-1 min-w-0">
          {event.server_endpoint}
        </span>

        {/* JSON-RPC id (optional) */}
        {event.jsonrpc_id !== null && event.jsonrpc_id !== undefined && (
          <span className="font-mono text-caption text-sentinel-text-tertiary tabular-nums shrink-0">
            id {String(event.jsonrpc_id)}
          </span>
        )}

        {/* Hover hint + chevron */}
        <span className="hidden md:group-hover:inline-flex md:items-center text-caption text-sentinel-accent shrink-0">
          View detail
        </span>
        <ChevronRight
          size={14}
          className="text-sentinel-text-tertiary shrink-0 transition-colors duration-150 group-hover:text-sentinel-text-secondary"
        />
      </div>
    </button>
  );
}

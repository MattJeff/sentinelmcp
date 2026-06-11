// Server card — one frosted tile per discovered MCP server.
// Implemented by Agent UI-2 for the Inventory page.

import clsx from 'clsx';
import type { ServerCard as ServerCardModel } from '../api/contract';
import { scopeLabel, scopeTooltip } from '../lib/scope';

export interface ServerCardProps {
  server: ServerCardModel;
  onSelect: (server: ServerCardModel) => void;
}

const STATUS_LABEL: Record<ServerCardModel['status'], string> = {
  approved: 'Approved',
  unknown: 'Unknown',
  suspect: 'Suspect',
  to_investigate: 'Investigate',
  blocked: 'Blocked',
};

const MAX_VISIBLE_TAGS = 5;

export default function ServerCard({ server, onSelect }: ServerCardProps) {
  const dotClass =
    server.color === 'green'
      ? 'dot-ok'
      : server.color === 'orange'
        ? 'dot-high'
        : 'dot-critical';

  const isRed = server.color === 'red';

  const tags = server.tags ?? [];
  const visibleTags = tags.slice(0, MAX_VISIBLE_TAGS);
  const overflow = tags.length - visibleTags.length;

  return (
    <button
      type="button"
      onClick={() => onSelect(server)}
      className={clsx(
        'card-hover text-left flex flex-col gap-4 w-full min-w-[280px]',
        'focus-visible:outline-none focus-visible:shadow-focus',
        isRed && 'border-l-2 border-l-sentinel-critical',
      )}
    >
      {/* Top row: dot + endpoint + transport pill */}
      <div className="flex items-start gap-3 min-w-0 w-full">
        <span
          className={clsx('dot mt-2 shrink-0', dotClass)}
          aria-hidden
        />
        <div className="flex-1 min-w-0">
          <div
            className="font-mono text-body font-semibold truncate text-sentinel-text-primary"
            title={server.endpoint}
          >
            {server.endpoint}
          </div>
          <div className="text-caption text-sentinel-text-tertiary mt-1 truncate">
            {STATUS_LABEL[server.status]}
          </div>
        </div>
        <span className="badge badge-neutral shrink-0">
          {server.transport}
        </span>
        {server.scope && (
          <span
            className={clsx(
              'badge shrink-0 max-w-[140px] truncate',
              server.scope.kind === 'user' ? 'badge-neutral' : 'badge-accent',
            )}
            title={scopeTooltip(server.scope)}
          >
            {scopeLabel(server.scope)}
          </span>
        )}
      </div>

      {/* Middle: scopes */}
      {server.scopes.length > 0 && (
        <div className="flex flex-wrap gap-2 min-w-0">
          {server.scopes.map((s) => (
            <span
              key={s}
              className="rounded-pill px-2 py-0.5 text-[11px] font-medium bg-sentinel-inset text-sentinel-text-tertiary border border-sentinel-border-soft truncate max-w-full"
            >
              {s}
            </span>
          ))}
        </div>
      )}

      {/* Bottom: tools + last seen */}
      <div className="text-caption text-sentinel-text-tertiary tabular-nums truncate">
        {server.tool_count} {server.tool_count === 1 ? 'tool' : 'tools'} ·{' '}
        Last seen {formatAppleDate(server.last_seen)}
      </div>

      {/* Tags — operator-curated labels, shown just above the trailing edge */}
      {tags.length > 0 && (
        <div
          className="flex flex-wrap gap-1 min-w-0"
          title={tags.join(', ')}
        >
          {visibleTags.map((tag) => (
            <span
              key={tag}
              className="rounded-pill px-2 py-0.5 text-[11px] font-medium bg-sentinel-accent-dim text-sentinel-accent border border-sentinel-accent/20 truncate max-w-full"
              title={tag}
            >
              {tag}
            </span>
          ))}
          {overflow > 0 && (
            <span
              className="rounded-pill px-2 py-0.5 text-[11px] font-medium bg-sentinel-inset text-sentinel-text-tertiary border border-sentinel-border tabular-nums"
              title={tags.slice(MAX_VISIBLE_TAGS).join(', ')}
            >
              +{overflow}
            </span>
          )}
        </div>
      )}
    </button>
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

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
      ? 'dot-green'
      : server.color === 'orange'
        ? 'dot-orange'
        : 'dot-red';

  const isRed = server.color === 'red';

  const tags = server.tags ?? [];
  const visibleTags = tags.slice(0, MAX_VISIBLE_TAGS);
  const overflow = tags.length - visibleTags.length;

  return (
    <button
      type="button"
      onClick={() => onSelect(server)}
      className={clsx(
        'card-hover text-left flex flex-col gap-3 w-full min-w-[280px]',
        isRed && 'shadow-glow-red',
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
            className="font-mono text-[14px] font-semibold truncate text-sentinel-text-primary"
            title={server.endpoint}
          >
            {server.endpoint}
          </div>
          <div className="text-[11px] text-sentinel-text-tertiary mt-0.5 truncate">
            {STATUS_LABEL[server.status]}
          </div>
        </div>
        <span
          className={clsx(
            'pill shrink-0',
            server.transport === 'http' ? 'pill-blue' : 'pill-green',
          )}
        >
          {server.transport}
        </span>
        {server.scope && (
          <span
            className={clsx(
              'pill shrink-0 max-w-[140px] truncate',
              server.scope.kind === 'user'
                ? 'bg-white/6 text-sentinel-text-secondary border border-white/10'
                : 'bg-teal-500/15 text-teal-200 border border-teal-400/30',
            )}
            title={scopeTooltip(server.scope)}
          >
            {scopeLabel(server.scope)}
          </span>
        )}
      </div>

      {/* Middle: scopes */}
      {server.scopes.length > 0 && (
        <div className="flex flex-wrap gap-1.5 min-w-0">
          {server.scopes.map((s) => (
            <span
              key={s}
              className="rounded-pill px-2 py-0.5 text-[10px] font-medium tracking-wide uppercase bg-white/6 text-sentinel-text-secondary border border-white/10 truncate max-w-full"
            >
              {s}
            </span>
          ))}
        </div>
      )}

      {/* Bottom: tools + last seen */}
      <div className="text-[11px] text-sentinel-text-tertiary truncate">
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
              className="rounded-pill px-2 py-0.5 text-[10px] font-medium bg-blue-500/15 text-blue-200 border border-blue-400/20 truncate max-w-full"
              title={tag}
            >
              {tag}
            </span>
          ))}
          {overflow > 0 && (
            <span
              className="rounded-pill px-2 py-0.5 text-[10px] font-medium bg-blue-500/10 text-blue-300/80 border border-blue-400/15"
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

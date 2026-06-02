// Inventory page — grid of MCP servers with sticky filter bar.
// Implemented by Agent UI-2, extended by Agent W15:
//   • auto-refresh on scan completion,
//   • Command-Palette deep-link via sessionStorage,
//   • last-refreshed sub-header with manual refresh,
//   • richer empty state with discovery CTA,
//   • severity-then-recency sort.

import type { DetailedHTMLProps, HTMLAttributes } from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import useSWR, { mutate } from 'swr';
import { RefreshCw, Telescope } from 'lucide-react';

import { api, onLiveTick, onScanProgress } from '../api/tauri';
import {
  COMMANDS,
  type ScanProgress,
  type ServerCard as ServerCardModel,
  type SeverityColor,
} from '../api/contract';
import ServerCard from '../components/ServerCard';
import ServerDetailDrawer from '../components/ServerDetailDrawer';
import FilterBar, {
  type ColorFilter,
  type StatusFilter,
  type TransportFilter,
} from '../components/FilterBar';

// Register a custom `<sub-header>` host element with JSX so we can render a
// semantic section without polluting the global tag registry.
declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'sub-header': DetailedHTMLProps<HTMLAttributes<HTMLElement>, HTMLElement>;
    }
  }
}

const PENDING_KEY = 'sentinel.pendingServerId';
const NAV_HINT_KEY = 'sentinel.pendingNavigation';

const COLOR_RANK: Record<SeverityColor, number> = {
  red: 0,
  orange: 1,
  green: 2,
};

export interface InventoryPageProps {
  onNavigate?: (pageId: string) => void;
}

export default function InventoryPage({ onNavigate }: InventoryPageProps = {}) {
  const { data, isLoading, mutate: revalidate } = useSWR<ServerCardModel[]>(
    COMMANDS.listServers,
    () => api.listServers(),
  );

  const [query, setQuery] = useState('');
  const [color, setColor] = useState<ColorFilter>('all');
  const [transport, setTransport] = useState<TransportFilter>('all');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<number>(() => Date.now());
  const [nowTick, setNowTick] = useState<number>(() => Date.now());

  const servers = data ?? [];

  // Re-tick once a second so the "N seconds ago" label stays live.
  useEffect(() => {
    const id = window.setInterval(() => setNowTick(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  // Track when SWR successfully refreshed (the data reference changed).
  useEffect(() => {
    if (data !== undefined) {
      setLastRefreshed(Date.now());
    }
  }, [data]);

  // Subscribe once to scan-progress; refresh the list when a scan finishes.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const off = await onScanProgress((p: ScanProgress) => {
        if (p.stage === 'finished') {
          mutate(COMMANDS.listServers);
        }
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  // Live background loop: refresh on every tick from the Rust watcher /
  // periodic scan, so a `claude mcp add` mutates the inventory automatically.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const off = await onLiveTick(() => {
        mutate(COMMANDS.listServers);
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  // Handle Command-Palette deep-links: open the drawer for the pending id.
  // We re-check whenever the dataset changes so the id is honoured even if
  // the page mounts before `listServers()` resolves.
  const consumedRef = useRef<string | null>(null);
  useEffect(() => {
    let pending: string | null = null;
    try {
      pending = sessionStorage.getItem(PENDING_KEY);
    } catch {
      pending = null;
    }
    if (!pending || consumedRef.current === pending) return;

    // Wait until we have at least loaded the list once so the drawer's
    // SWR fetch lines up with a real server id.
    if (data === undefined) return;

    consumedRef.current = pending;
    setSelectedId(pending);
    try {
      sessionStorage.removeItem(PENDING_KEY);
    } catch {
      /* ignore */
    }
  }, [data]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const result = servers.filter((s) => {
      if (color !== 'all' && s.color !== color) return false;
      if (transport !== 'all' && s.transport !== transport) return false;
      if (status !== 'all') {
        if (status === 'suspect') {
          // Treat both suspect and to_investigate as suspect bucket.
          if (s.status !== 'suspect' && s.status !== 'to_investigate') {
            return false;
          }
        } else if (s.status !== status) {
          return false;
        }
      }
      if (q) {
        const haystack = [
          s.endpoint,
          s.transport,
          ...s.scopes,
        ]
          .join(' ')
          .toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });

    // Sort: red > orange > green, then by `last_seen` desc.
    return [...result].sort((a, b) => {
      const rankDiff = COLOR_RANK[a.color] - COLOR_RANK[b.color];
      if (rankDiff !== 0) return rankDiff;
      // last_seen is ISO-8601; lexicographic sort matches chronological order.
      if (a.last_seen > b.last_seen) return -1;
      if (a.last_seen < b.last_seen) return 1;
      return 0;
    });
  }, [servers, query, color, transport, status]);

  const handleSelect = (server: ServerCardModel) => {
    setSelectedId(server.id);
    // eslint-disable-next-line no-console
    console.log('[Inventory] selected server', server.id, server.endpoint);
  };

  const handleManualRefresh = useCallback(() => {
    revalidate();
  }, [revalidate]);

  const handleDiscoveryCta = useCallback(() => {
    if (onNavigate) {
      onNavigate('discovery');
      return;
    }
    try {
      sessionStorage.setItem(NAV_HINT_KEY, 'discovery');
    } catch {
      /* ignore */
    }
  }, [onNavigate]);

  const secondsAgo = Math.max(0, Math.floor((nowTick - lastRefreshed) / 1000));
  const refreshedLabel =
    secondsAgo < 5
      ? 'Last refreshed just now'
      : `Last refreshed ${secondsAgo} second${secondsAgo === 1 ? '' : 's'} ago`;

  return (
    <div className="animate-fade-up w-full max-w-[1600px] mx-auto">
      <sub-header
        // Custom element name kept lowercased with a dash so React treats it
        // as a host element (declared in JSX intrinsics above).
        className="flex items-center justify-between mb-3 text-[12px] text-sentinel-text-tertiary"
      >
        <span aria-live="polite">{refreshedLabel}</span>
        <button
          type="button"
          onClick={handleManualRefresh}
          className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-sentinel-text-secondary hover:text-white hover:bg-white/10 transition-colors"
          aria-label="Refresh inventory"
        >
          <RefreshCw className="h-3 w-3" />
          Refresh
        </button>
      </sub-header>

      <FilterBar
        query={query}
        onQueryChange={setQuery}
        color={color}
        onColorChange={setColor}
        transport={transport}
        onTransportChange={setTransport}
        status={status}
        onStatusChange={setStatus}
        visibleCount={filtered.length}
      />

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="card min-w-[280px]">
              <div className="skeleton h-4 w-2/3 mb-3" />
              <div className="skeleton h-3 w-1/2 mb-2" />
              <div className="skeleton h-3 w-1/3" />
            </div>
          ))}
        </div>
      ) : servers.length === 0 ? (
        <div className="glass rounded-glass p-10 text-center flex flex-col items-center gap-4">
          <div className="h-12 w-12 rounded-full bg-gradient-to-br from-sentinel-blue/30 to-sentinel-purple/30 flex items-center justify-center">
            <Telescope className="h-6 w-6 text-sentinel-blue-glow" />
          </div>
          <div>
            <div className="text-[15px] font-semibold mb-1">
              No MCP servers in your inventory yet.
            </div>
            <div className="text-[13px] text-sentinel-text-secondary max-w-md mx-auto">
              Sentinel hasn’t observed any MCP traffic on this Mac. Run a
              discovery scan to enumerate every AI client and the servers it
              declares — they’ll show up here as soon as they’re seen.
            </div>
          </div>
          <button
            type="button"
            onClick={handleDiscoveryCta}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-sentinel-blue to-sentinel-purple px-4 py-2 text-[13px] font-medium text-white shadow-glow-blue hover:opacity-90 transition-opacity"
          >
            <Telescope className="h-4 w-4" />
            Run a discovery scan
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="glass rounded-glass p-10 text-center">
          <div className="text-[15px] font-semibold mb-1">
            No servers match these filters.
          </div>
          <div className="text-[13px] text-sentinel-text-secondary">
            Try widening the colour, status, or transport filters.
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((server) => (
            <ServerCard
              key={server.id}
              server={server}
              onSelect={handleSelect}
            />
          ))}
        </div>
      )}

      {/* Live region for screen readers — announces the selected server. */}
      {selectedId && (
        <div className="sr-only" aria-live="polite">
          Selected server {selectedId}
        </div>
      )}

      <ServerDetailDrawer
        serverId={selectedId}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}

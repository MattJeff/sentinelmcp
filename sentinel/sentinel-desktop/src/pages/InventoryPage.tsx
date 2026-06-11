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

import { api, onLiveTick, onLookalikeRescanDone, onScanProgress } from '../api/tauri';
import {
  COMMANDS,
  type ScanProgress,
  type ServerCard as ServerCardModel,
  type SeverityColor,
} from '../api/contract';
import { useToastStore } from '../hooks/useToast';
import ServerCard from '../components/ServerCard';
import ServerDetailDrawer from '../components/ServerDetailDrawer';
import FilterBar, {
  type ColorFilter,
  type ScopeFilter,
  type StatusFilter,
  type TransportFilter,
} from '../components/FilterBar';
import { matchesScopeFilter } from '../lib/scope';

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

  // Tag pool used by the multi-select filter. Re-fetched whenever the server
  // list mutates so newly-minted tags surface without a page reload.
  const { data: tagPool } = useSWR<string[]>(
    COMMANDS.serverListTags,
    () => api.serverListTags(),
  );

  const [query, setQuery] = useState('');
  const [color, setColor] = useState<ColorFilter>('all');
  const [transport, setTransport] = useState<TransportFilter>('all');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>('all');
  const [selectedProjectPaths, setSelectedProjectPaths] = useState<string[]>([]);
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
          mutate(COMMANDS.serverListTags);
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
        mutate(COMMANDS.serverListTags);
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  // Auto lookalike rescan feedback: when `probe_server` transitions a
  // server from "failed" / "no record" to "success", the Rust side spawns
  // a single-server lookalike scan and emits this event on completion.
  // Surface it as a toast so the operator immediately knows whether the
  // newcomer is a doppelganger candidate without re-running the manual
  // scan from the Discovery page.
  const pushToast = useToastStore((s) => s.push);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const off = await onLookalikeRescanDone(({ server_id, matches_count }) => {
        if (matches_count === 0) {
          pushToast({
            title: 'Lookalike rescan',
            description: `No new matches for ${server_id}`,
            severity: 'info',
          });
        } else {
          pushToast({
            title: 'Lookalike rescan',
            description: `${matches_count} match${matches_count === 1 ? '' : 'es'} found for ${server_id}`,
            severity: matches_count >= 2 ? 'high' : 'medium',
          });
        }
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [pushToast]);

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

  // Distinct project paths in the current inventory — feeds the FilterBar
  // multi-select that appears when the Scope bucket is set to "project".
  const availableProjectPaths = useMemo(() => {
    const set = new Set<string>();
    for (const s of servers) {
      if (s.scope?.kind === 'project') set.add(s.scope.path);
    }
    return Array.from(set).sort();
  }, [servers]);

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
      // Scope bucket filter — `matchesScopeFilter` defaults missing scopes
      // to "user" so older payloads still slot into the User bucket.
      if (!matchesScopeFilter(s.scope, scopeFilter)) return false;
      // When narrowed to "project" with at least one path selected, keep
      // only servers whose project path is in the whitelist.
      if (
        scopeFilter === 'project' &&
        selectedProjectPaths.length > 0 &&
        s.scope?.kind === 'project'
      ) {
        if (!selectedProjectPaths.includes(s.scope.path)) return false;
      }
      // Tag filter: intersection semantics — every selected tag must be
      // present on the server. Empty selection = no filtering.
      if (selectedTags.length > 0) {
        const own = new Set(s.tags ?? []);
        for (const tag of selectedTags) {
          if (!own.has(tag)) return false;
        }
      }
      if (q) {
        const haystack = [
          s.endpoint,
          s.transport,
          ...s.scopes,
          ...(s.tags ?? []),
          s.scope?.kind === 'project' ? s.scope.path : '',
          s.scope?.kind ?? '',
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
  }, [
    servers,
    query,
    color,
    transport,
    status,
    selectedTags,
    scopeFilter,
    selectedProjectPaths,
  ]);

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
    <div className="animate-fade-up w-full max-w-[1400px] mx-auto">
      <sub-header
        // Custom element name kept lowercased with a dash so React treats it
        // as a host element (declared in JSX intrinsics above).
        className="flex items-center justify-between mb-4 text-caption text-sentinel-text-tertiary"
      >
        <span aria-live="polite" className="tabular-nums">{refreshedLabel}</span>
        <button
          type="button"
          onClick={handleManualRefresh}
          className="btn btn-sm"
          aria-label="Refresh inventory"
        >
          <RefreshCw className="h-3 w-3" aria-hidden />
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
        selectedTags={selectedTags}
        onSelectedTagsChange={setSelectedTags}
        availableTags={tagPool ?? []}
        scope={scopeFilter}
        onScopeChange={setScopeFilter}
        availableProjectPaths={availableProjectPaths}
        selectedProjectPaths={selectedProjectPaths}
        onSelectedProjectPathsChange={setSelectedProjectPaths}
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
        <div className="surface rounded-glass px-8 py-12 text-center flex flex-col items-center gap-6">
          <div className="h-12 w-12 rounded-full bg-sentinel-accent-dim flex items-center justify-center">
            <Telescope className="h-6 w-6 text-sentinel-accent" aria-hidden />
          </div>
          <div className="flex flex-col gap-2">
            <div className="text-title text-sentinel-text-primary">
              No MCP servers in your inventory yet.
            </div>
            <div className="text-body text-sentinel-text-secondary max-w-md mx-auto">
              Sentinel hasn’t observed any MCP traffic on this Mac. Run a
              discovery scan to enumerate every AI client and the servers it
              declares — they’ll show up here as soon as they’re seen.
            </div>
          </div>
          <button
            type="button"
            onClick={handleDiscoveryCta}
            className="btn btn-primary"
          >
            <Telescope className="h-4 w-4" aria-hidden />
            Run a discovery scan
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="surface rounded-glass px-8 py-12 text-center flex flex-col gap-2">
          <div className="text-title text-sentinel-text-primary">
            No servers match these filters.
          </div>
          <div className="text-body text-sentinel-text-secondary">
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

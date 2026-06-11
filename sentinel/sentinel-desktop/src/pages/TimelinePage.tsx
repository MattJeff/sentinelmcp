// TimelinePage — Time-travel: replay every JSON-RPC envelope Sentinel has
// captured on the wire. Sticky filter row, KPI tiles, and a (rough)
// virtualized list of EventRow that loads more on demand.
// Implemented by Agent U3.

import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import { Clock, Layers, Radio } from 'lucide-react';

import { api } from '../api/tauri';
import type {
  ObservedDirection,
  ObservedEvent,
  ObservedEventFilter,
  ServerCard as ServerCardModel,
} from '../api/contract';
import EventRow from '../components/timeline/EventRow';
import EventDetailDrawer from '../components/timeline/EventDetailDrawer';

type DirectionFilter = 'all' | ObservedDirection;
type DateRange = 'today' | '7d' | '30d' | 'custom';

const PAGE = 200;

const DIRECTION_OPTIONS: { value: DirectionFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'client_to_server', label: 'client to server' },
  { value: 'server_to_client', label: 'server to client' },
];

const DATE_OPTIONS: { value: DateRange; label: string }[] = [
  { value: 'today', label: 'Today' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: 'custom', label: 'Custom' },
];

function startOfDay(d: Date): Date {
  const c = new Date(d);
  c.setHours(0, 0, 0, 0);
  return c;
}

function rangeBounds(
  range: DateRange,
  customFrom: string,
  customTo: string,
): { since: Date | null; until: Date | null } {
  const now = new Date();
  if (range === 'today') {
    return { since: startOfDay(now), until: null };
  }
  if (range === '7d') {
    const d = new Date(now);
    d.setDate(d.getDate() - 7);
    return { since: d, until: null };
  }
  if (range === '30d') {
    const d = new Date(now);
    d.setDate(d.getDate() - 30);
    return { since: d, until: null };
  }
  // custom
  const since = customFrom ? new Date(customFrom) : null;
  const until = customTo ? new Date(customTo) : null;
  return {
    since: since && !Number.isNaN(since.getTime()) ? since : null,
    until: until && !Number.isNaN(until.getTime()) ? until : null,
  };
}

function humanizeSpan(ms: number): string {
  if (ms <= 0) return '—';
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    const remMin = minutes % 60;
    return remMin ? `${hours}h ${remMin}m` : `${hours}h`;
  }
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours ? `${days}d ${remHours}h` : `${days}d`;
}

export default function TimelinePage() {
  const { data: servers } = useSWR<ServerCardModel[]>(
    'list_servers',
    () => api.listServers(),
  );

  // Filters
  const [serverId, setServerId] = useState<string>('all');
  const [method, setMethod] = useState<string>('all');
  const [direction, setDirection] = useState<DirectionFilter>('all');
  const [range, setRange] = useState<DateRange>('30d');
  const [customFrom, setCustomFrom] = useState<string>('');
  const [customTo, setCustomTo] = useState<string>('');

  // Build the backend filter — kept narrow on purpose; we still re-filter on
  // the client so the user gets instant feedback while typing.
  const backendFilter = useMemo<ObservedEventFilter>(() => {
    const { since, until } = rangeBounds(range, customFrom, customTo);
    const f: ObservedEventFilter = {};
    if (serverId !== 'all') f.server_id = serverId;
    if (method !== 'all') f.method = method;
    if (direction !== 'all') f.direction = direction;
    if (since) f.since = since.toISOString();
    if (until) f.until = until.toISOString();
    return f;
  }, [serverId, method, direction, range, customFrom, customTo]);

  const swrKey = useMemo(
    () => ['list_observed_events', JSON.stringify(backendFilter)],
    [backendFilter],
  );
  const { data, isLoading } = useSWR<ObservedEvent[]>(swrKey, () =>
    api.listObservedEvents(backendFilter),
  );

  const events = data ?? [];

  // Client-side re-filter — matches the backend filter on the same fields so
  // the mock and real backend behave identically.
  const filteredAll = useMemo(() => {
    const { since, until } = rangeBounds(range, customFrom, customTo);
    return events
      .filter((e) => {
        if (serverId !== 'all' && e.server_id !== serverId) return false;
        if (method !== 'all' && e.method !== method) return false;
        if (direction !== 'all' && e.direction !== direction) return false;
        if (since && new Date(e.timestamp) < since) return false;
        if (until && new Date(e.timestamp) > until) return false;
        return true;
      })
      .sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );
  }, [events, serverId, method, direction, range, customFrom, customTo]);

  // Rough virtualization: render the first N, then "Load more".
  const [visibleCount, setVisibleCount] = useState(PAGE);
  useEffect(() => {
    setVisibleCount(PAGE);
  }, [serverId, method, direction, range, customFrom, customTo]);
  const visible = filteredAll.slice(0, visibleCount);
  const hasMore = filteredAll.length > visibleCount;

  // Selected row (drives the drawer)
  const [selected, setSelected] = useState<ObservedEvent | null>(null);

  // KPI tiles
  const kpi = useMemo(() => {
    if (filteredAll.length === 0) {
      return { total: 0, sessions: 0, spanLabel: '—' };
    }
    const sessions = new Set(filteredAll.map((e) => e.session_id));
    const times = filteredAll.map((e) => new Date(e.timestamp).getTime());
    const span = Math.max(...times) - Math.min(...times);
    return {
      total: filteredAll.length,
      sessions: sessions.size,
      spanLabel: humanizeSpan(span),
    };
  }, [filteredAll]);

  // Method dropdown options derived from data so we never show stale methods.
  const methodOptions = useMemo(() => {
    const set = new Set<string>();
    for (const e of events) set.add(e.method);
    return ['all', ...Array.from(set).sort()];
  }, [events]);

  // Server dropdown options — derived from the events the backend actually
  // returned so the dropdown can never offer a server with zero traffic.
  // The inventory list is used only to enrich the label when available.
  const serverOptions = useMemo(() => {
    const labelById = new Map<string, string>();
    for (const s of servers ?? []) labelById.set(s.id, s.endpoint);
    const list: { id: string; label: string }[] = [];
    const seen = new Set<string>();
    for (const e of events) {
      if (seen.has(e.server_id)) continue;
      seen.add(e.server_id);
      list.push({
        id: e.server_id,
        label: labelById.get(e.server_id) ?? e.server_endpoint,
      });
    }
    list.sort((a, b) => a.label.localeCompare(b.label));
    return list;
  }, [servers, events]);

  // Cross-page navigation helper. The active page lives in App.tsx as React
  // state and there is no router/store we can pull in from this page, so we
  // trigger a click on the sidebar nav button — the canonical setter for the
  // active page (see DashboardLayout's NavItem buttons, which use
  // aria-label = item.label).
  const navigateTo = (sidebarLabel: string) => {
    const el = document.querySelector<HTMLButtonElement>(
      `button[aria-label="${sidebarLabel}"]`,
    );
    el?.click();
  };

  const hasAnyEvents = events.length > 0;

  return (
    <div className="animate-fade-up mx-auto w-full max-w-[1400px]">
      {/* KPI tiles */}
      <div className="grid grid-cols-1 min-[900px]:grid-cols-3 gap-4 mb-6">
        <KpiTile
          icon={<Layers size={16} />}
          label="Total events"
          value={kpi.total.toLocaleString()}
        />
        <KpiTile
          icon={<Radio size={16} />}
          label="Unique sessions"
          value={kpi.sessions.toLocaleString()}
        />
        <KpiTile
          icon={<Clock size={16} />}
          label="Time covered"
          value={kpi.spanLabel}
        />
      </div>

      {/* Sticky filter row */}
      <div className="sticky top-0 z-10 -mx-4 px-4 sm:-mx-6 sm:px-6 pb-4 pt-1 mb-6 bg-sentinel-raised">
        <div className="surface rounded-glass p-4 flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <FilterField label="Server">
              <select
                className="input text-caption min-w-[200px]"
                value={serverId}
                onChange={(e) => setServerId(e.target.value)}
              >
                <option value="all">All servers</option>
                {serverOptions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </FilterField>

            <FilterField label="Method">
              <select
                className="input text-caption min-w-[160px]"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
              >
                {methodOptions.map((m) => (
                  <option key={m} value={m}>
                    {m === 'all' ? 'All methods' : m}
                  </option>
                ))}
              </select>
            </FilterField>

            <FilterField label="Direction">
              <div className="flex flex-wrap items-center gap-1.5">
                {DIRECTION_OPTIONS.map((opt) => {
                  const active = direction === opt.value;
                  return (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setDirection(opt.value)}
                      className={clsx(
                        'pill transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus',
                        active
                          ? 'pill-blue'
                          : 'text-sentinel-text-secondary bg-sentinel-inset border border-sentinel-border hover:bg-sentinel-raised hover:border-sentinel-border-strong hover:text-sentinel-text-primary',
                      )}
                    >
                      {opt.label}
                    </button>
                  );
                })}
              </div>
            </FilterField>

            <FilterField label="Range">
              <div className="flex flex-wrap items-center gap-1.5">
                {DATE_OPTIONS.map((opt) => {
                  const active = range === opt.value;
                  return (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setRange(opt.value)}
                      className={clsx(
                        'pill transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus',
                        active
                          ? 'pill-blue'
                          : 'text-sentinel-text-secondary bg-sentinel-inset border border-sentinel-border hover:bg-sentinel-raised hover:border-sentinel-border-strong hover:text-sentinel-text-primary',
                      )}
                    >
                      {opt.label}
                    </button>
                  );
                })}
              </div>
            </FilterField>

            <div className="ml-auto text-caption text-sentinel-text-tertiary tabular-nums">
              {filteredAll.length}{' '}
              {filteredAll.length === 1 ? 'event' : 'events'}
            </div>
          </div>

          {range === 'custom' && (
            <div className="flex flex-wrap items-center gap-3">
              <FilterField label="From">
                <input
                  type="datetime-local"
                  className="input text-caption"
                  value={customFrom}
                  onChange={(e) => setCustomFrom(e.target.value)}
                />
              </FilterField>
              <FilterField label="To">
                <input
                  type="datetime-local"
                  className="input text-caption"
                  value={customTo}
                  onChange={(e) => setCustomTo(e.target.value)}
                />
              </FilterField>
            </div>
          )}
        </div>
      </div>

      {/* Feed */}
      {isLoading && events.length === 0 ? (
        <div className="flex flex-col gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="glass-soft rounded-glass p-4">
              <div className="skeleton h-3 w-2/3 mb-2" />
              <div className="skeleton h-3 w-1/3" />
            </div>
          ))}
        </div>
      ) : filteredAll.length === 0 ? (
        !hasAnyEvents ? (
          <div className="surface rounded-glass px-8 py-12 text-center flex flex-col items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-sentinel-accent-dim text-sentinel-accent">
              <Clock size={18} />
            </div>
            <div className="text-title text-sentinel-text-primary">
              The timeline is empty.
            </div>
            <div className="text-body text-sentinel-text-secondary max-w-md">
              Sentinel hasn&apos;t captured any JSON-RPC traffic yet. Run a
              scan to populate the timeline — every observed envelope will
              appear here.
            </div>
            <button
              type="button"
              className="btn btn-primary no-drag mt-2"
              onClick={() => navigateTo('Live Scan')}
            >
              Run a scan to populate the timeline
            </button>
          </div>
        ) : (
          <div className="surface rounded-glass px-8 py-12 text-center">
            <div className="text-title text-sentinel-text-primary mb-2">
              No traffic in this window.
            </div>
            <div className="text-body text-sentinel-text-secondary">
              Widen the date range or clear filters to see captured events.
            </div>
          </div>
        )
      ) : (
        <div className="flex flex-col gap-3">
          {visible.map((e) => (
            <EventRow key={e.id} event={e} onSelect={setSelected} />
          ))}
          {hasMore && (
            <div className="pt-2 flex justify-center">
              <button
                type="button"
                className="btn no-drag"
                onClick={() => setVisibleCount((n) => n + PAGE)}
              >
                Load more
                <span className="ml-1 text-sentinel-text-tertiary tabular-nums">
                  ({filteredAll.length - visibleCount} left)
                </span>
              </button>
            </div>
          )}
        </div>
      )}

      <EventDetailDrawer
        event={selected}
        onClose={() => setSelected(null)}
        onShowInInventory={(id) => {
          // Persist the target server in the same sessionStorage slot the
          // Inventory page already consumes on mount, then flip the active
          // page by clicking the sidebar's Inventory nav button.
          try {
            window.sessionStorage.setItem('sentinel.pendingServerId', id);
          } catch {
            // sessionStorage can throw in private/locked-down shells —
            // navigation should still happen even if we can't drop the hint.
          }
          navigateTo('Inventory');
        }}
      />
    </div>
  );
}

interface FilterFieldProps {
  label: string;
  children: React.ReactNode;
}

function FilterField({ label, children }: FilterFieldProps) {
  return (
    <label className="flex flex-wrap items-center gap-2 min-w-0">
      <span className="section-heading">{label}</span>
      {children}
    </label>
  );
}

interface KpiTileProps {
  icon: React.ReactNode;
  label: string;
  value: string;
}

function KpiTile({ icon, label, value }: KpiTileProps) {
  return (
    <div className="card min-w-0 flex items-center gap-4">
      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sentinel-accent-dim text-sentinel-accent shrink-0">
        {icon}
      </div>
      <div className="min-w-0">
        <div className="text-overline text-sentinel-text-tertiary">
          {label}
        </div>
        <div className="text-metric font-semibold tabular-nums mt-1">
          {value}
        </div>
      </div>
    </div>
  );
}

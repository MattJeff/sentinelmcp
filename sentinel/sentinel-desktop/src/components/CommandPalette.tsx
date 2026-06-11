// Cmd+K command palette — frosted glass, Radix Dialog.
// Owned by Agent UI-11. Searches servers, findings, and static pages.
//
// The keyboard binding lives in `useCommandPalette`; this component is fully
// controllable through `open` / `onOpenChange` so it can also be opened by a
// future trigger button in DashboardLayout.

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import clsx from 'clsx';
import useSWR from 'swr';
import {
  AlertCircle,
  Activity,
  BarChart3,
  CheckSquare,
  CornerDownLeft,
  FileText,
  LayoutGrid,
  Search,
  Server,
  ShieldCheck,
  Settings as SettingsIcon,
  Wrench,
} from 'lucide-react';

import { api } from '../api/tauri';
import type { Finding, ServerCard } from '../api/contract';

export type CommandPaletteSection =
  | 'recent'
  | 'servers'
  | 'tools'
  | 'findings'
  | 'pages';

const RECENT_STORAGE_KEY = 'sentinel.palette.recent';
const RECENT_LIMIT = 3;

function loadRecentKeys(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((x): x is string => typeof x === 'string');
  } catch {
    return [];
  }
}

function saveRecentKeys(keys: string[]) {
  try {
    localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(keys));
  } catch {
    // ignore — private mode / quota.
  }
}

export type CommandPalettePageId =
  | 'overview'
  | 'inventory'
  | 'scan'
  | 'alerts'
  | 'approvals'
  | 'compliance'
  | 'report'
  | 'settings';

interface PaletteItem {
  key: string;
  section: CommandPaletteSection;
  label: string;
  caption: string;
  icon: typeof Search;
  // Discriminated payload — the parent only sees the right callback.
  payload:
    | { kind: 'page'; id: CommandPalettePageId }
    | { kind: 'server'; id: string }
    | { kind: 'finding'; id: string }
    | { kind: 'tool'; serverId: string; name: string };
}

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onNavigate?: (pageId: CommandPalettePageId) => void;
  onSelectServer?: (id: string) => void;
  onSelectFinding?: (id: string) => void;
}

const PAGES: Array<{
  id: CommandPalettePageId;
  label: string;
  caption: string;
  icon: typeof Search;
}> = [
  { id: 'overview', label: 'Overview', caption: 'High-level dashboard', icon: LayoutGrid },
  { id: 'inventory', label: 'Inventory', caption: 'Every server, every tool', icon: ShieldCheck },
  { id: 'scan', label: 'Scan', caption: 'Live MCP capture', icon: Activity },
  { id: 'alerts', label: 'Alerts', caption: 'Rug-pulls and poisoning', icon: AlertCircle },
  { id: 'approvals', label: 'Approvals', caption: 'Decide each server', icon: CheckSquare },
  { id: 'compliance', label: 'Compliance', caption: 'OWASP, SAFE-MCP, SOC 2', icon: BarChart3 },
  { id: 'report', label: 'Report', caption: 'Signed audit bundle', icon: FileText },
  { id: 'settings', label: 'Settings', caption: 'Channels and retention', icon: SettingsIcon },
];

const SECTION_LABEL: Record<CommandPaletteSection, string> = {
  recent: 'Recent',
  servers: 'Servers',
  tools: 'Tools',
  findings: 'Findings',
  pages: 'Pages',
};

const SECTION_ORDER: CommandPaletteSection[] = [
  'recent',
  'pages',
  'servers',
  'tools',
  'findings',
];

export default function CommandPalette({
  open,
  onOpenChange,
  onNavigate,
  onSelectServer,
  onSelectFinding,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [recentKeys, setRecentKeys] = useState<string[]>(() => loadRecentKeys());
  const listRef = useRef<HTMLDivElement>(null);

  // Only fetch while open — keep network quiet otherwise.
  const { data: servers } = useSWR<ServerCard[]>(
    open ? 'palette:list_servers' : null,
    () => api.listServers(),
    { revalidateOnFocus: false },
  );
  const { data: findings } = useSWR<Finding[]>(
    open ? 'palette:list_findings' : null,
    () => api.listFindings(),
    { revalidateOnFocus: false },
  );

  // Reset query + cursor each time the palette opens, and rehydrate recents
  // (another window/tab may have updated localStorage).
  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      setRecentKeys(loadRecentKeys());
    }
  }, [open]);

  const items = useMemo<PaletteItem[]>(() => {
    const out: PaletteItem[] = [];

    for (const page of PAGES) {
      out.push({
        key: `page:${page.id}`,
        section: 'pages',
        label: page.label,
        caption: page.caption,
        icon: page.icon,
        payload: { kind: 'page', id: page.id },
      });
    }

    for (const server of servers ?? []) {
      out.push({
        key: `server:${server.id}`,
        section: 'servers',
        label: server.endpoint,
        caption: `${server.transport} · ${server.status}`,
        icon: Server,
        payload: { kind: 'server', id: server.id },
      });
    }

    for (const finding of findings ?? []) {
      out.push({
        key: `finding:${finding.id}`,
        section: 'findings',
        label: finding.title,
        caption: `${finding.severity} · ${finding.server_id.slice(0, 8)}`,
        icon: AlertCircle,
        payload: { kind: 'finding', id: finding.id },
      });
    }

    // Tools — derive from SWR cache if a server detail was already fetched.
    // Hook intentionally omitted: contract says skip unless cached. SWR cache
    // access from here without subscribing would be brittle; we leave the
    // section empty until a future iteration adds a tools index.

    // Recent — clone the last N selected items into the `recent` section so
    // they appear at the top of the list. Order: most-recent first.
    if (recentKeys.length > 0) {
      const byKey = new Map(out.map((item) => [item.key, item]));
      for (const key of recentKeys.slice(0, RECENT_LIMIT)) {
        const src = byKey.get(key);
        if (!src) continue;
        out.push({
          ...src,
          key: `recent:${src.key}`,
          section: 'recent',
        });
      }
    }

    return out;
  }, [servers, findings, recentKeys]);

  const filtered = useMemo(() => fuzzyFilter(items, query), [items, query]);

  // Reset cursor when the result set changes so we never land out of bounds.
  useEffect(() => {
    setActiveIndex(0);
  }, [query, filtered.length]);

  const grouped = useMemo(() => groupBySection(filtered), [filtered]);
  const flat = useMemo(() => flattenGrouped(grouped), [grouped]);

  const close = useCallback(() => onOpenChange(false), [onOpenChange]);

  const select = useCallback(
    (item: PaletteItem) => {
      switch (item.payload.kind) {
        case 'page':
          onNavigate?.(item.payload.id);
          break;
        case 'server':
          onSelectServer?.(item.payload.id);
          break;
        case 'finding':
          onSelectFinding?.(item.payload.id);
          break;
        case 'tool':
          onSelectServer?.(item.payload.serverId);
          break;
      }
      // Track in recents using the canonical key (strip the `recent:` prefix
      // when the user picked from the Recent section itself).
      const canonicalKey = item.key.startsWith('recent:')
        ? item.key.slice('recent:'.length)
        : item.key;
      setRecentKeys((prev) => {
        const next = [canonicalKey, ...prev.filter((k) => k !== canonicalKey)].slice(
          0,
          RECENT_LIMIT,
        );
        saveRecentKeys(next);
        return next;
      });
      close();
    },
    [onNavigate, onSelectServer, onSelectFinding, close],
  );

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (flat.length === 0) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((i) => (i + 1) % flat.length);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((i) => (i - 1 + flat.length) % flat.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const item = flat[activeIndex];
      if (item) select(item);
    }
  }

  // Scroll the active row into view as the user navigates.
  useEffect(() => {
    const root = listRef.current;
    if (!root) return;
    const el = root.querySelector<HTMLElement>(
      `[data-palette-index="${activeIndex}"]`,
    );
    el?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-xs data-[state=open]:animate-fade-up"
        />
        <Dialog.Content
          aria-describedby={undefined}
          onKeyDown={onKeyDown}
          className={clsx(
            'surface-raised shadow-overlay fixed left-1/2 z-50 -translate-x-1/2 rounded-glass overflow-hidden',
            'data-[state=open]:animate-fade-up',
          )}
          style={{
            top: '18vh',
            width: 'min(640px, calc(100vw - 2rem))',
          }}
        >
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>

          {/* Input */}
          <div className="flex items-center gap-3 px-6 py-4 border-b border-sentinel-border-soft">
            <Search
              className="h-4 w-4 shrink-0 text-sentinel-text-tertiary"
              aria-hidden
            />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search servers, tools, findings…"
              className={clsx(
                'flex-1 bg-transparent border-0 outline-none',
                'text-[15px] leading-5 text-sentinel-text-primary',
                'placeholder:text-sentinel-text-faint',
              )}
              spellCheck={false}
              autoComplete="off"
            />
            <kbd className="hidden sm:inline-flex items-center rounded-pill border border-sentinel-border bg-white/4 px-2 py-1 text-overline text-sentinel-text-tertiary">
              Esc
            </kbd>
          </div>

          {/* Results */}
          <div
            ref={listRef}
            className="max-h-[52vh] overflow-y-auto py-2"
            role="listbox"
          >
            {flat.length === 0 ? (
              <EmptyState />
            ) : (
              SECTION_ORDER.map((section) => {
                const rows = grouped[section];
                if (!rows || rows.length === 0) return null;
                return (
                  <div key={section} className="mb-2">
                    <div className="section-heading px-6 pt-3 pb-2">
                      {SECTION_LABEL[section]}
                    </div>
                    <div className="px-2">
                      {rows.map(({ item, index }) => (
                        <Row
                          key={item.key}
                          item={item}
                          active={index === activeIndex}
                          flatIndex={index}
                          onSelect={() => select(item)}
                          onHover={() => setActiveIndex(index)}
                        />
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between gap-3 border-t border-sentinel-border-soft px-6 py-3">
            <span className="text-overline text-sentinel-text-tertiary">
              Sentinel command palette
            </span>
            <span className="text-caption text-sentinel-text-faint tabular-nums">
              ↑↓ navigate · ↵ select · esc close
            </span>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Row ────────────────────────────────────────────────────────────────

interface RowProps {
  item: PaletteItem;
  active: boolean;
  flatIndex: number;
  onSelect: () => void;
  onHover: () => void;
}

function Row({ item, active, flatIndex, onSelect, onHover }: RowProps) {
  const Icon = item.icon;
  return (
    <button
      type="button"
      role="option"
      aria-selected={active}
      data-palette-index={flatIndex}
      onClick={onSelect}
      onMouseMove={onHover}
      className={clsx(
        'group flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors duration-150',
        'focus-visible:outline-none focus-visible:shadow-focus',
        active
          ? 'bg-sentinel-raised text-sentinel-text-primary'
          : 'text-sentinel-text-secondary hover:bg-sentinel-raised hover:text-sentinel-text-primary',
      )}
    >
      <Icon
        className={clsx(
          'h-4 w-4 shrink-0',
          active ? 'text-sentinel-accent' : 'text-sentinel-text-tertiary',
        )}
        aria-hidden
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-body font-medium text-sentinel-text-primary">
          {item.label}
        </div>
        <div className="truncate text-caption text-sentinel-text-tertiary">
          {item.caption}
        </div>
      </div>
      <CornerDownLeft
        className={clsx(
          'h-3.5 w-3.5 shrink-0 text-sentinel-text-tertiary transition-opacity',
          active ? 'opacity-100' : 'opacity-0 group-hover:opacity-100',
        )}
        aria-hidden
      />
    </button>
  );
}

// ── Empty state ────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="px-6 py-12 text-center">
      <div className="text-body text-sentinel-text-secondary">
        No matches. Try a different word.
      </div>
      <div className="mt-2 text-caption text-sentinel-text-tertiary">
        Press{' '}
        <kbd className="inline-flex items-center rounded-pill border border-sentinel-border bg-white/4 px-2 py-1 text-overline text-sentinel-text-tertiary">
          ⌘K
        </kbd>{' '}
        anywhere to open this palette.
      </div>
    </div>
  );
}

// Silence unused-import warning for Wrench — reserved for the Tools section
// once a tools index lands. Keeping it referenced avoids removing/restoring
// the import in a future iteration.
void Wrench;

// ── Search + grouping ──────────────────────────────────────────────────

/**
 * Fuzzy substring matching, case-insensitive. Tokens (split on whitespace)
 * must each appear somewhere in `label + caption`. Empty query returns all.
 * Sorted by earliest match position to surface the most relevant hit first.
 */
function fuzzyFilter(items: PaletteItem[], query: string): PaletteItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  const tokens = q.split(/\s+/).filter(Boolean);

  const scored: Array<{ item: PaletteItem; score: number }> = [];
  for (const item of items) {
    const haystack = `${item.label} ${item.caption}`.toLowerCase();
    let ok = true;
    let bestPos = Number.MAX_SAFE_INTEGER;
    for (const token of tokens) {
      const pos = haystack.indexOf(token);
      if (pos === -1) {
        ok = false;
        break;
      }
      if (pos < bestPos) bestPos = pos;
    }
    if (ok) scored.push({ item, score: bestPos });
  }

  scored.sort((a, b) => a.score - b.score);
  return scored.map((s) => s.item);
}

type GroupedRow = { item: PaletteItem; index: number };

function groupBySection(
  items: PaletteItem[],
): Record<CommandPaletteSection, GroupedRow[]> {
  const result: Record<CommandPaletteSection, GroupedRow[]> = {
    recent: [],
    pages: [],
    servers: [],
    tools: [],
    findings: [],
  };
  // Walk in SECTION_ORDER so the global flat index matches visual order.
  let cursor = 0;
  for (const section of SECTION_ORDER) {
    for (const item of items) {
      if (item.section !== section) continue;
      result[section].push({ item, index: cursor });
      cursor += 1;
    }
  }
  return result;
}

function flattenGrouped(
  grouped: Record<CommandPaletteSection, GroupedRow[]>,
): PaletteItem[] {
  const out: PaletteItem[] = [];
  for (const section of SECTION_ORDER) {
    for (const row of grouped[section]) out.push(row.item);
  }
  return out;
}

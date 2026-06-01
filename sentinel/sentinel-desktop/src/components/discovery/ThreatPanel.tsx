// ThreatPanel — surface the bundled `FluxMenaces` threat-intel feed.
//
// Lists every known-bad MCP package (typosquats, poisoning incidents,
// rug-pulls, revoked maintainers). Rows where the user's own MCP servers
// match a threat are highlighted in red; the common case (no match) is
// shown in tertiary text so the panel stays a passive reference.

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import { AlertTriangle, Loader2, Search, ShieldAlert } from 'lucide-react';

import { api } from '@/api/tauri';
import { COMMANDS, type ThreatEntry } from '@/api/contract';

/** Sort/severity helper — UI mirrors the Rust side so column sorts agree. */
function severityRank(s: string): number {
  switch (s) {
    case 'critical':
      return 3;
    case 'high':
      return 2;
    case 'medium':
      return 1;
    default:
      return 0;
  }
}

function severityPillClass(s: string, danger: boolean): string {
  if (danger) return 'pill pill-red';
  switch (s) {
    case 'critical':
      return 'pill pill-red';
    case 'high':
      return 'pill pill-orange';
    case 'medium':
      return 'pill pill-amber';
    default:
      return 'pill bg-white/6 border border-white/10 text-sentinel-text-tertiary';
  }
}

type SortKey = 'matches' | 'severity' | 'published' | 'id' | 'package';

interface SortState {
  key: SortKey;
  /** true = descending */
  desc: boolean;
}

const DEFAULT_SORT: SortState = { key: 'matches', desc: true };

function compareEntries(a: ThreatEntry, b: ThreatEntry, sort: SortState): number {
  let v = 0;
  switch (sort.key) {
    case 'matches':
      v = a.matches_count - b.matches_count;
      break;
    case 'severity':
      v = severityRank(a.severity) - severityRank(b.severity);
      break;
    case 'published':
      v = a.published_at.localeCompare(b.published_at);
      break;
    case 'id':
      v = a.identifier.localeCompare(b.identifier);
      break;
    case 'package':
      v = a.package_name.localeCompare(b.package_name);
      break;
  }
  return sort.desc ? -v : v;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n - 1).trimEnd()}…`;
}

function ColumnHeader({
  label,
  k,
  sort,
  setSort,
  align = 'left',
}: {
  label: string;
  k: SortKey;
  sort: SortState;
  setSort: (s: SortState) => void;
  align?: 'left' | 'right';
}) {
  const active = sort.key === k;
  return (
    <button
      type="button"
      onClick={() =>
        setSort({ key: k, desc: active ? !sort.desc : true })
      }
      className={clsx(
        'section-heading hover:text-sentinel-text-secondary transition-colors',
        align === 'right' && 'text-right w-full',
      )}
    >
      {label}
      {active && (
        <span className="ml-1 text-[9px]">{sort.desc ? '↓' : '↑'}</span>
      )}
    </button>
  );
}

export default function ThreatPanel() {
  const { data, isValidating, error } = useSWR<ThreatEntry[]>(
    COMMANDS.listThreats,
    api.listThreats,
    { revalidateOnFocus: false, revalidateOnReconnect: false },
  );

  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<SortState>(DEFAULT_SORT);

  const entries = data ?? [];

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const base = q
      ? entries.filter(
          (e) =>
            e.package_name.toLowerCase().includes(q) ||
            e.identifier.toLowerCase().includes(q),
        )
      : entries;
    return [...base].sort((a, b) => compareEntries(a, b, sort));
  }, [entries, query, sort]);

  const matchCount = entries.filter((e) => e.matches_count > 0).length;

  return (
    <section className="card flex flex-col gap-4">
      {/* Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="flex items-start gap-3">
          <div className="h-9 w-9 shrink-0 rounded-xl bg-white/8 border border-white/10 flex items-center justify-center">
            <ShieldAlert
              className="h-4.5 w-4.5 text-sentinel-text-primary"
              aria-hidden
            />
          </div>
          <div>
            <h3 className="text-[15px] font-semibold tracking-tight">
              Threat intelligence feed ({entries.length} entries)
            </h3>
            <p className="text-[12px] text-sentinel-text-secondary">
              Curated list of known-bad MCP packages, typosquats, and poisoning
              incidents.
              {matchCount > 0 && (
                <>
                  {' '}
                  <span className="text-sentinel-red font-semibold">
                    {matchCount} match
                    {matchCount === 1 ? '' : 'es'} on your Mac.
                  </span>
                </>
              )}
            </p>
          </div>
        </div>
        <div className="relative w-full md:w-72">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-sentinel-text-tertiary"
            aria-hidden
          />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by package or ID"
            className="input pl-8 w-full min-h-[44px]"
            aria-label="Filter threat feed"
          />
        </div>
      </div>

      {/* Body */}
      {error ? (
        <div className="text-[12px] text-sentinel-red">
          Failed to load threat feed: {String(error)}
        </div>
      ) : !data && isValidating ? (
        <div className="flex items-center gap-2 text-[12px] text-sentinel-text-secondary">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          Loading threat feed…
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-[12px] text-sentinel-text-tertiary py-6 text-center">
          No entries match the current filter.
        </div>
      ) : (
        <div className="overflow-x-auto -mx-2">
          <table className="w-full text-[12px] border-separate border-spacing-y-1.5 px-2">
            <thead>
              <tr>
                <th className="text-left px-2">
                  <ColumnHeader label="ID" k="id" sort={sort} setSort={setSort} />
                </th>
                <th className="text-left px-2">
                  <ColumnHeader
                    label="Package"
                    k="package"
                    sort={sort}
                    setSort={setSort}
                  />
                </th>
                <th className="text-left px-2">
                  <ColumnHeader
                    label="Severity"
                    k="severity"
                    sort={sort}
                    setSort={setSort}
                  />
                </th>
                <th className="text-left px-2 section-heading">Reason</th>
                <th className="hidden md:table-cell text-left px-2 section-heading">Refs</th>
                <th className="hidden md:table-cell text-left px-2">
                  <ColumnHeader
                    label="Published"
                    k="published"
                    sort={sort}
                    setSort={setSort}
                  />
                </th>
                <th className="text-right px-2">
                  <ColumnHeader
                    label="Matches"
                    k="matches"
                    sort={sort}
                    setSort={setSort}
                    align="right"
                  />
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => {
                const danger = e.matches_count > 0;
                return (
                  <tr
                    key={e.identifier}
                    className={clsx(
                      'rounded-glass',
                      danger
                        ? 'bg-sentinel-red/10 shadow-glow-red'
                        : 'bg-white/4',
                    )}
                  >
                    <td
                      className={clsx(
                        'px-2 py-2 font-mono text-[11.5px] rounded-l-glass',
                        danger
                          ? 'text-sentinel-text-primary'
                          : 'text-sentinel-text-tertiary',
                      )}
                    >
                      {e.identifier}
                    </td>
                    <td
                      className={clsx(
                        'px-2 py-2 font-mono text-[11.5px] max-w-[240px] truncate',
                        danger
                          ? 'text-sentinel-text-primary'
                          : 'text-sentinel-text-tertiary',
                      )}
                      title={e.package_name}
                    >
                      {e.package_name}
                    </td>
                    <td className="px-2 py-2">
                      <span className={severityPillClass(e.severity, danger)}>
                        {e.severity}
                      </span>
                    </td>
                    <td
                      className={clsx(
                        'px-2 py-2 max-w-[280px]',
                        danger
                          ? 'text-sentinel-text-secondary'
                          : 'text-sentinel-text-tertiary',
                      )}
                      title={e.reason}
                    >
                      {truncate(e.reason, 90)}
                    </td>
                    <td className="hidden md:table-cell px-2 py-2">
                      <div className="flex flex-wrap gap-1">
                        {e.references.length === 0 ? (
                          <span className="text-sentinel-text-tertiary">—</span>
                        ) : (
                          e.references.map((r) => (
                            <span
                              key={r}
                              className="pill bg-white/6 border border-white/10 text-sentinel-text-secondary py-0.5 px-1.5 text-[10px] normal-case tracking-normal"
                            >
                              {r}
                            </span>
                          ))
                        )}
                      </div>
                    </td>
                    <td
                      className={clsx(
                        'hidden md:table-cell px-2 py-2 font-mono text-[11px]',
                        danger
                          ? 'text-sentinel-text-secondary'
                          : 'text-sentinel-text-tertiary',
                      )}
                    >
                      {e.published_at}
                    </td>
                    <td
                      className={clsx(
                        'px-2 py-2 text-right font-semibold rounded-r-glass',
                        danger
                          ? 'text-sentinel-red'
                          : 'text-sentinel-text-tertiary',
                      )}
                    >
                      {danger ? (
                        <span className="inline-flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" aria-hidden />
                          {e.matches_count}
                        </span>
                      ) : (
                        <span>0</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

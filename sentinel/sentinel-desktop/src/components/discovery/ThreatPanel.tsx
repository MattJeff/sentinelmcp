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
  if (danger) return 'badge badge-critical';
  switch (s) {
    case 'critical':
      return 'badge badge-critical';
    case 'high':
      return 'badge badge-high';
    case 'medium':
      return 'badge badge-medium';
    default:
      return 'badge badge-neutral';
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
        'section-heading rounded transition-colors duration-150 hover:text-sentinel-text-secondary focus-visible:outline-none focus-visible:shadow-focus',
        align === 'right' && 'text-right w-full',
      )}
      aria-pressed={active}
    >
      {label}
      {active && (
        <span className="ml-1 text-[9px]" aria-hidden>
          {sort.desc ? '↓' : '↑'}
        </span>
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
    <section className="card flex flex-col gap-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex items-start gap-3">
          <div className="h-9 w-9 shrink-0 rounded-lg bg-sentinel-inset border border-sentinel-border flex items-center justify-center">
            <ShieldAlert
              className="h-4.5 w-4.5 text-sentinel-text-secondary"
              aria-hidden
            />
          </div>
          <div className="flex flex-col gap-1">
            <h3 className="text-title text-sentinel-text-primary">
              Threat intelligence feed ({entries.length} entries)
            </h3>
            <p className="text-caption text-sentinel-text-secondary max-w-prose">
              Curated list of known-bad MCP packages, typosquats, and poisoning
              incidents.
              {matchCount > 0 && (
                <>
                  {' '}
                  <span className="text-sentinel-critical font-medium">
                    {matchCount} match
                    {matchCount === 1 ? '' : 'es'} on your Mac.
                  </span>
                </>
              )}
            </p>
          </div>
        </div>
        <div className="relative w-full md:w-72 shrink-0">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-sentinel-text-tertiary"
            aria-hidden
          />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by package or ID"
            className="input pl-8 w-full"
            aria-label="Filter threat feed"
          />
        </div>
      </div>

      {/* Body */}
      {error ? (
        <div
          className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-caption text-sentinel-critical"
          role="alert"
        >
          Failed to load threat feed: {String(error)}
        </div>
      ) : !data && isValidating ? (
        <div className="flex items-center justify-center gap-2 py-8 text-caption text-sentinel-text-secondary">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          Loading threat feed…
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border border-dashed border-sentinel-border py-8 text-center text-caption text-sentinel-text-tertiary">
          No entries match the current filter.
        </div>
      ) : (
        <div className="overflow-x-auto -mx-2">
          <table className="w-full text-body border-separate border-spacing-y-2 px-2">
            <thead>
              <tr>
                <th className="text-left px-3 pb-1">
                  <ColumnHeader label="ID" k="id" sort={sort} setSort={setSort} />
                </th>
                <th className="text-left px-3 pb-1">
                  <ColumnHeader
                    label="Package"
                    k="package"
                    sort={sort}
                    setSort={setSort}
                  />
                </th>
                <th className="text-left px-3 pb-1">
                  <ColumnHeader
                    label="Severity"
                    k="severity"
                    sort={sort}
                    setSort={setSort}
                  />
                </th>
                <th className="text-left px-3 pb-1 section-heading">Reason</th>
                <th className="hidden md:table-cell text-left px-3 pb-1 section-heading">Refs</th>
                <th className="hidden md:table-cell text-left px-3 pb-1">
                  <ColumnHeader
                    label="Published"
                    k="published"
                    sort={sort}
                    setSort={setSort}
                  />
                </th>
                <th className="text-right px-3 pb-1">
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
                      'transition-colors duration-150',
                      danger
                        ? 'bg-sentinel-critical-bg'
                        : 'bg-sentinel-inset hover:bg-sentinel-raised',
                    )}
                  >
                    <td
                      className={clsx(
                        'px-3 py-3 font-mono text-caption rounded-l-lg border-l-2',
                        danger
                          ? 'border-sentinel-critical text-sentinel-text-primary'
                          : 'border-transparent text-sentinel-text-tertiary',
                      )}
                    >
                      {e.identifier}
                    </td>
                    <td
                      className={clsx(
                        'px-3 py-3 font-mono text-caption max-w-[240px] truncate',
                        danger
                          ? 'text-sentinel-text-primary'
                          : 'text-sentinel-text-tertiary',
                      )}
                      title={e.package_name}
                    >
                      {e.package_name}
                    </td>
                    <td className="px-3 py-3">
                      <span className={severityPillClass(e.severity, danger)}>
                        {e.severity}
                      </span>
                    </td>
                    <td
                      className={clsx(
                        'px-3 py-3 max-w-[280px]',
                        danger
                          ? 'text-sentinel-text-secondary'
                          : 'text-sentinel-text-tertiary',
                      )}
                      title={e.reason}
                    >
                      {truncate(e.reason, 90)}
                    </td>
                    <td className="hidden md:table-cell px-3 py-3">
                      <div className="flex flex-wrap gap-1">
                        {e.references.length === 0 ? (
                          <span className="text-sentinel-text-tertiary">—</span>
                        ) : (
                          e.references.map((r) => (
                            <span
                              key={r}
                              className="badge badge-neutral !px-1.5 !py-0 !text-[10px] !tracking-normal normal-case"
                            >
                              {r}
                            </span>
                          ))
                        )}
                      </div>
                    </td>
                    <td
                      className={clsx(
                        'hidden md:table-cell px-3 py-3 font-mono text-caption tabular-nums',
                        danger
                          ? 'text-sentinel-text-secondary'
                          : 'text-sentinel-text-tertiary',
                      )}
                    >
                      {e.published_at}
                    </td>
                    <td
                      className={clsx(
                        'px-3 py-3 text-right font-semibold tabular-nums rounded-r-lg',
                        danger
                          ? 'text-sentinel-critical'
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

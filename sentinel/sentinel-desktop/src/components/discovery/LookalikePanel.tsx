// LookalikePanel — surface registry-backed brand doppelgangers.
//
// Runs the `scan_lookalikes` Tauri command: cross-references every MCP
// server declared on this Mac against PulseMCP / Smithery / mcp.so /
// mcp-registry using the brand-similarity engine from `sentinel-detect`.
// Matches whose name is *not* byte-equal to a declared server but whose
// combined similarity score is ≥ 0.85 are likely typo-squats.

import { useCallback, useState } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import { Copy, Loader2, Radar } from 'lucide-react';

import { api } from '@/api/tauri';
import { COMMANDS, type LookalikeMatch, type Settings } from '@/api/contract';
import LookalikeDetailDialog from './LookalikeDetailDialog';

const SCAN_TIMEOUT_MS = 15_000;

function severityPillClass(s: string): string {
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

function scoreLabel(score: number): string {
  return `${(score * 100).toFixed(1)}%`;
}

/** Race a promise against a hard timeout — surfaces a clean error to the UI. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(
      () => reject(new Error(`scan timed out after ${ms / 1000}s`)),
      ms,
    );
    promise.then(
      (v) => {
        window.clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        window.clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/* L14 filter bar */
type SourceFilter = 'all' | 'registry' | 'intra-inventory';
type SignalFilter = 'all' | 'enum-overlap' | 'tool-overlap' | 'name-only';

/** Read L11's optional `source` field defensively (parallel branch). */
function matchSource(m: LookalikeMatch): 'registry' | 'intra-inventory' {
  const s = (m as unknown as { source?: string }).source;
  return s === 'intra-inventory' ? 'intra-inventory' : 'registry';
}

/** Read L11's optional `signals` field defensively (parallel branch). */
function matchSignals(m: LookalikeMatch): string[] {
  const sig = (m as unknown as { signals?: string[] }).signals;
  return Array.isArray(sig) ? sig : [];
}

function signalCategory(m: LookalikeMatch): SignalFilter {
  const sig = matchSignals(m);
  if (sig.includes('enum-overlap')) return 'enum-overlap';
  if (sig.includes('tool-overlap')) return 'tool-overlap';
  return 'name-only';
}

/* L13 — surface L11's provenance + per-component fields */

/** Read L11's optional `score_breakdown` defensively. */
function matchBreakdown(m: LookalikeMatch): {
  name: number;
  description: number;
  tools: number;
  enums: number;
} | null {
  const raw = (m as unknown as {
    score_breakdown?: {
      name?: unknown;
      description?: unknown;
      tools?: unknown;
      enums?: unknown;
    };
  }).score_breakdown;
  if (!raw || typeof raw !== 'object') return null;
  const num = (v: unknown): number => (typeof v === 'number' ? v : 0);
  return {
    name: num(raw.name),
    description: num(raw.description),
    tools: num(raw.tools),
    enums: num(raw.enums),
  };
}

function sourceLabel(s: 'registry' | 'intra-inventory'): string {
  return s === 'intra-inventory' ? 'Intra-inventory' : 'Registry';
}

function sourcePillClass(s: 'registry' | 'intra-inventory'): string {
  return s === 'intra-inventory' ? 'pill pill-violet' : 'pill pill-blue';
}

export default function LookalikePanel() {
  const [matches, setMatches] = useState<LookalikeMatch[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all');
  const [signalFilter, setSignalFilter] = useState<SignalFilter>('all');
  // L15 — detail dialog
  const [detailRow, setDetailRow] = useState<LookalikeMatch | null>(null);

  // Mirror the global "Outbound calls" toggle so the Scan button matches the
  // gating already in place on TAXII/SIEM/email/webhook test buttons. Fall
  // back to enabled on hydration failure so a transient load error doesn't
  // strand the operator.
  const { data: settings } = useSWR<Settings>(
    COMMANDS.getSettings,
    () => api.getSettings(),
    { revalidateOnFocus: false },
  );
  const outboundEnabled = settings?.privacy?.outbound_lookups ?? false;

  const handleScan = useCallback(async () => {
    if (!outboundEnabled) return;
    setLoading(true);
    setError(null);
    try {
      const rows = await withTimeout(api.scanLookalikes(), SCAN_TIMEOUT_MS);
      setMatches(rows);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setMatches(null);
    } finally {
      setLoading(false);
    }
  }, [outboundEnabled]);

  return (
    <section className="card flex flex-col gap-4">
      {/* Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="flex items-start gap-3">
          <div className="h-9 w-9 shrink-0 rounded-xl bg-white/8 border border-white/10 flex items-center justify-center">
            <Radar
              className="h-4.5 w-4.5 text-sentinel-text-primary"
              aria-hidden
            />
          </div>
          <div>
            <h3 className="text-[15px] font-semibold tracking-tight">
              Lookalike scan
            </h3>
            <p className="text-[12px] text-sentinel-text-secondary max-w-prose">
              Cross-reference each declared MCP server on this Mac against the
              public registries (PulseMCP, Smithery, mcp.so, mcp-registry) to
              flag suspicious doppelganger packages.
              {matches && matches.length > 0 && (
                <>
                  {' '}
                  <span className="text-sentinel-red font-semibold">
                    {matches.length} lookalike
                    {matches.length === 1 ? '' : 's'} detected.
                  </span>
                </>
              )}
            </p>
          </div>
        </div>
        <button
          type="button"
          className="btn btn-primary min-h-[44px] w-full sm:w-auto justify-center"
          onClick={() => void handleScan()}
          disabled={loading || !outboundEnabled}
          title={
            !outboundEnabled
              ? 'Disabled — Outbound calls are turned off.'
              : 'Cross-reference declared MCP servers against public registries'
          }
        >
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          ) : (
            <Radar className="h-4 w-4" aria-hidden />
          )}
          {loading ? 'Scanning…' : 'Scan registries'}
        </button>
      </div>

      {/* Body */}
      {error ? (
        <div className="text-[12px] text-sentinel-red">
          Lookalike scan failed: {error}
        </div>
      ) : matches === null ? (
        <div className="text-[12px] text-sentinel-text-tertiary py-6 text-center">
          Click <span className="font-semibold text-sentinel-text-primary">Scan registries</span>{' '}
          to run a fresh sweep.
        </div>
      ) : matches.length === 0 ? (
        <div className="text-[12px] text-sentinel-text-tertiary py-6 text-center">
          No lookalikes detected against your inventory.
        </div>
      ) : (
        (() => {
          /* L14 filter bar */
          const sourceCounts = {
            all: matches.length,
            registry: matches.filter((m) => matchSource(m) === 'registry').length,
            'intra-inventory': matches.filter(
              (m) => matchSource(m) === 'intra-inventory',
            ).length,
          } as const;
          const signalCounts = {
            all: matches.length,
            'enum-overlap': matches.filter(
              (m) => signalCategory(m) === 'enum-overlap',
            ).length,
            'tool-overlap': matches.filter(
              (m) => signalCategory(m) === 'tool-overlap',
            ).length,
            'name-only': matches.filter(
              (m) => signalCategory(m) === 'name-only',
            ).length,
          } as const;
          const filtered = matches.filter((m) => {
            if (sourceFilter !== 'all' && matchSource(m) !== sourceFilter)
              return false;
            if (signalFilter !== 'all' && signalCategory(m) !== signalFilter)
              return false;
            return true;
          });
          const pillBase = 'pill cursor-pointer select-none';
          const pillActive = 'pill-blue';
          const pillIdle =
            'bg-white/6 border border-white/10 text-sentinel-text-tertiary';
          const sourceOptions: { key: SourceFilter; label: string }[] = [
            { key: 'all', label: 'All' },
            { key: 'registry', label: 'Registry' },
            { key: 'intra-inventory', label: 'Intra-inventory' },
          ];
          const signalOptions: { key: SignalFilter; label: string }[] = [
            { key: 'all', label: 'All' },
            { key: 'enum-overlap', label: 'Enum-driven' },
            { key: 'tool-overlap', label: 'Tool-overlap' },
            { key: 'name-only', label: 'Name-only' },
          ];
          return (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-2 rounded-glass bg-white/4 border border-white/8 px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="section-heading text-[11px] mr-1">
                    Source
                  </span>
                  {sourceOptions.map((opt) => {
                    const active = sourceFilter === opt.key;
                    return (
                      <button
                        key={opt.key}
                        type="button"
                        onClick={() => setSourceFilter(opt.key)}
                        className={clsx(pillBase, active ? pillActive : pillIdle)}
                        aria-pressed={active}
                      >
                        {opt.label}
                        <span className="ml-1 opacity-70">
                          {sourceCounts[opt.key]}
                        </span>
                      </button>
                    );
                  })}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="section-heading text-[11px] mr-1">
                    Signal
                  </span>
                  {signalOptions.map((opt) => {
                    const active = signalFilter === opt.key;
                    return (
                      <button
                        key={opt.key}
                        type="button"
                        onClick={() => setSignalFilter(opt.key)}
                        className={clsx(pillBase, active ? pillActive : pillIdle)}
                        aria-pressed={active}
                      >
                        {opt.label}
                        <span className="ml-1 opacity-70">
                          {signalCounts[opt.key]}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
              {filtered.length === 0 ? (
                <div className="text-[12px] text-sentinel-text-tertiary py-6 text-center">
                  No matches for the selected filters.
                </div>
              ) : (
                <div className="overflow-x-auto -mx-2">
                  <table className="w-full text-[12px] border-separate border-spacing-y-1.5 px-2">
                    <thead>
                      <tr>
                        <th className="text-left px-2 section-heading">Severity</th>
                        <th className="text-left px-2 section-heading">Source</th>
                        <th className="text-left px-2 section-heading">Declared</th>
                        <th className="text-left px-2 section-heading">Registry</th>
                        <th className="text-left px-2 section-heading">Candidate</th>
                        <th className="text-right px-2 section-heading">Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((m, idx) => {
                const danger = m.severity === 'critical';
                return (
                  <tr
                    key={`${m.declared_package}::${m.registry}::${m.candidate_name}::${idx}`}
                    className={clsx(
                      'rounded-glass cursor-pointer hover:bg-white/8 focus:outline-none focus-visible:ring-1 focus-visible:ring-sentinel-blue-glow/60',
                      danger
                        ? 'bg-sentinel-red/10 shadow-glow-red'
                        : 'bg-white/4',
                    )}
                    onClick={() => setDetailRow(m)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setDetailRow(m);
                      }
                    }}
                    role="button"
                    tabIndex={0}
                    aria-label={`Open match details for ${m.candidate_name}`}
                  >
                    <td className="px-2 py-2 rounded-l-glass">
                      <span className={severityPillClass(m.severity)}>
                        {m.severity}
                      </span>
                    </td>
                    <td className="px-2 py-2">
                      <span className={sourcePillClass(matchSource(m))}>
                        {sourceLabel(matchSource(m))}
                      </span>
                    </td>
                    <td
                      className={clsx(
                        'px-2 py-2 font-mono text-[11.5px] max-w-[200px] truncate',
                        danger
                          ? 'text-sentinel-text-primary'
                          : 'text-sentinel-text-secondary',
                      )}
                      title={m.declared_package}
                    >
                      <span className="inline-flex items-center gap-1.5">
                        <Copy className="h-3 w-3 opacity-60" aria-hidden />
                        {m.declared_package}
                      </span>
                    </td>
                    <td
                      className={clsx(
                        'px-2 py-2 font-mono text-[11.5px]',
                        danger
                          ? 'text-sentinel-text-primary'
                          : 'text-sentinel-text-tertiary',
                      )}
                    >
                      {m.registry}
                    </td>
                    <td
                      className={clsx(
                        'px-2 py-2 max-w-[260px]',
                        danger
                          ? 'text-sentinel-text-primary'
                          : 'text-sentinel-text-secondary',
                      )}
                      title={
                        m.candidate_description
                          ? `${m.candidate_name} — ${m.candidate_description}`
                          : m.candidate_name
                      }
                    >
                      <div className="flex flex-col gap-1">
                        <span className="font-mono text-[11.5px] truncate">
                          {m.candidate_name}
                        </span>
                        {matchSignals(m).length > 0 && (
                          <span className="flex flex-wrap gap-1">
                            {matchSignals(m).map((sig) => (
                              <span
                                key={sig}
                                className="pill pill-cyan !px-1.5 !py-0 !text-[9.5px] !tracking-normal normal-case"
                              >
                                {sig}
                              </span>
                            ))}
                          </span>
                        )}
                      </div>
                    </td>
                    <td
                      className={clsx(
                        'px-2 py-2 text-right rounded-r-glass',
                        danger
                          ? 'text-sentinel-red'
                          : 'text-sentinel-text-secondary',
                      )}
                    >
                      <div className="flex flex-col items-end gap-0.5">
                        <span className="font-semibold">
                          {scoreLabel(m.similarity_score)}
                        </span>
                        {(() => {
                          const b = matchBreakdown(m);
                          if (!b) return null;
                          return (
                            <span className="text-[10px] text-sentinel-text-tertiary font-mono">
                              name {b.name.toFixed(2)} · desc{' '}
                              {b.description.toFixed(2)} · tools{' '}
                              {b.tools.toFixed(2)} · enums{' '}
                              {b.enums.toFixed(2)}
                            </span>
                          );
                        })()}
                      </div>
                    </td>
                  </tr>
                );
              })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          );
        })()
      )}

      {/* L15 — per-row score breakdown dialog */}
      <LookalikeDetailDialog
        row={detailRow}
        onOpenChange={(open) => {
          if (!open) setDetailRow(null);
        }}
      />
    </section>
  );
}

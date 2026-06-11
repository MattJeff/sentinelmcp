// TrustGraphPage — frosted-glass interactive view of "who can reach what",
// with a Blast Radius score per AI client.
//
// Originally built by agent U2 (which derived the graph client-side from
// `api.discoverSystem()`). Rewired by agent W8 to call the real Rust trust
// graph computed by `sentinel_discovery::ConstructeurGraphe` via the new
// `compute_trust_graph` Tauri command.

import { useEffect, useMemo, useState } from 'react';
import useSWR, { useSWRConfig } from 'swr';
import { Loader2, Network } from 'lucide-react';

import { api, onLiveTick } from '../api/tauri';
import { COMMANDS, type TrustGraphComputed } from '../api/contract';
import GraphCanvas, {
  type TrustEdge,
  type TrustNode,
} from '../components/graph/GraphCanvas';
import BlastRadiusBar from '../components/graph/BlastRadiusBar';

// Map a Rust-side scope tag to a 0..1 risk for coloring scope chips.
// Mirrors the weights `ConstructeurGraphe::score_blast_radius` uses. The
// Rust side now emits English tags: `browser`, `network`, `external_api`,
// `database`, `unknown` (plus the long-standing `filesystem`, `secrets`,
// `read`, `write`).
function scopeRisk(scope: string): number {
  switch (scope) {
    case 'secrets':
      return 1.0;
    case 'filesystem':
      return 0.7;
    case 'database':
      return 0.6;
    case 'external_api':
      return 0.45;
    case 'network':
    case 'browser':
      return 0.35;
    case 'write':
      return 0.55;
    case 'read':
      return 0.25;
    default:
      return 0.4;
  }
}

// ─── Page ──────────────────────────────────────────────────────────────────

export default function TrustGraphPage() {
  const { data, isLoading, isValidating, error } = useSWR<TrustGraphComputed>(
    COMMANDS.computeTrustGraph,
    () => api.computeTrustGraph(),
  );
  const { mutate } = useSWRConfig();

  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Live background loop: recompute the trust graph whenever a fresh scan
  // lands so blast-radius rankings reflect the current declared topology.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const off = await onLiveTick(() => {
        void mutate(COMMANDS.computeTrustGraph);
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [mutate]);

  const graph: TrustGraphComputed =
    data ?? { nodes: [], edges: [], max_blast_radius: 0 };

  // Split nodes by kind once for the various views below.
  const clientNodes = useMemo(
    () => graph.nodes.filter((n) => n.kind === 'client'),
    [graph.nodes],
  );
  const serverNodes = useMemo(
    () => graph.nodes.filter((n) => n.kind === 'server'),
    [graph.nodes],
  );

  const serverById = useMemo(
    () => new Map(serverNodes.map((s) => [s.id, s] as const)),
    [serverNodes],
  );

  // Adjacency: client id → server ids it reaches.
  const clientServerIds = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const c of clientNodes) m.set(c.id, []);
    for (const e of graph.edges) {
      const list = m.get(e.from);
      if (list && !list.includes(e.to)) list.push(e.to);
    }
    return m;
  }, [clientNodes, graph.edges]);

  const ranked = useMemo(() => {
    return [...clientNodes]
      .map((c) => ({
        client: c,
        score: c.blast_radius ?? 0,
        serverIds: clientServerIds.get(c.id) ?? [],
      }))
      .sort((a, b) => b.score - a.score);
  }, [clientNodes, clientServerIds]);

  const maxBlast = graph.max_blast_radius;
  const topClientId = ranked[0]?.client.id ?? null;

  // Build the visualisation node/edge sets: clients + servers + one node per
  // unique scope, with `server → scope` edges so scopes float as chips.
  const { nodes, edges } = useMemo(() => {
    const ns: TrustNode[] = [];
    const es: TrustEdge[] = [];

    for (const { client, score } of ranked) {
      ns.push({ id: client.id, label: client.label, kind: 'client', score });
    }
    for (const srv of serverNodes) {
      ns.push({ id: srv.id, label: srv.label, kind: 'server' });
    }

    const seenScopes = new Set<string>();
    for (const srv of serverNodes) {
      for (const sc of srv.scopes) {
        const id = `scope:${sc}`;
        if (!seenScopes.has(sc)) {
          seenScopes.add(sc);
          ns.push({ id, label: sc, kind: 'scope', risk: scopeRisk(sc) });
        }
        es.push({ source: srv.id, target: id });
      }
    }

    for (const e of graph.edges) {
      es.push({ source: e.from, target: e.to });
    }
    return { nodes: ns, edges: es };
  }, [ranked, serverNodes, graph.edges]);

  const selected = ranked.find((r) => r.client.id === selectedId) ?? null;
  const selectedBreakdown = useMemo(() => {
    if (!selected) return [];
    return selected.serverIds
      .map((sid) => {
        const srv = serverById.get(sid);
        if (!srv) return null;
        return { name: srv.label, scopes: srv.scopes };
      })
      .filter((x): x is { name: string; scopes: string[] } => x !== null);
  }, [selected, serverById]);

  return (
    <div className="flex flex-col gap-8">
      {/* Header — titre et sous-titre déjà fournis par DashboardLayout */}
      <header className="flex justify-end animate-fade-up">
        <button
          type="button"
          className="btn btn-sm gap-2 self-start shrink-0"
          onClick={() => void mutate(COMMANDS.computeTrustGraph)}
          disabled={isValidating}
          title="Recompute the trust graph from the latest discovered topology"
          aria-label="Refresh trust graph"
        >
          {isValidating ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          ) : (
            <Network className="h-3.5 w-3.5" aria-hidden />
          )}
          Live topology
        </button>
      </header>

      {error && (
        <div className="animate-fade-up" role="alert">
          <span className="badge badge-critical gap-2">
            <span className="dot dot-critical" aria-hidden />
            {String((error as Error)?.message ?? error)}
          </span>
        </div>
      )}

      {/* KPI row */}
      <section className="grid gap-4 grid-cols-1 md:grid-cols-3 animate-fade-up">
        <Kpi
          label="AI clients"
          value={isLoading ? null : clientNodes.length}
        />
        <Kpi
          label="MCP servers"
          value={isLoading ? null : serverNodes.length}
        />
        <Kpi
          label="Max blast radius"
          value={isLoading ? null : maxBlast.toFixed(0)}
          emphasised={maxBlast > 0}
        />
      </section>

      {/* Graph + blast list */}
      <section className="grid gap-4 grid-cols-1 lg:grid-cols-3 animate-fade-up">
        <div className="card min-w-0 lg:col-span-2 flex flex-col gap-4 min-h-[40vh] lg:min-h-[560px]">
          <div className="flex items-center justify-between gap-4">
            <h2 className="text-title text-sentinel-text-primary">
              Reachability
            </h2>
            <div className="section-heading">clients · servers · scopes</div>
          </div>
          <div className="flex-1 min-h-[40vh] lg:min-h-[60vh] rounded-glass overflow-hidden bg-sentinel-inset border border-sentinel-border-soft">
            {isLoading ? (
              <div className="h-full w-full skeleton" />
            ) : (
              <GraphCanvas
                nodes={nodes}
                edges={edges}
                selectedId={selectedId}
                pulseId={topClientId}
                onSelect={setSelectedId}
              />
            )}
          </div>
          <div className="text-caption text-sentinel-text-tertiary">
            Hover a node to focus its paths. Click an AI client for its blast-radius breakdown.
          </div>
        </div>

        <aside className="card min-w-0 flex flex-col gap-4">
          <div className="flex items-center justify-between gap-4">
            <h2 className="text-title text-sentinel-text-primary">
              Blast radius
            </h2>
            <div className="section-heading">Sorted</div>
          </div>

          {isLoading ? (
            <div className="flex flex-col gap-2">
              {[0, 1, 2].map((i) => (
                <div key={i} className="skeleton h-12 w-full" />
              ))}
            </div>
          ) : ranked.length === 0 ? (
            <div className="rounded-lg border border-dashed border-sentinel-border px-4 py-8 text-center text-caption text-sentinel-text-tertiary">
              No AI clients discovered yet.
            </div>
          ) : (
            <ul className="flex flex-col gap-2">
              {ranked.map(({ client, score }) => (
                <li key={client.id}>
                  <button
                    type="button"
                    onClick={() =>
                      setSelectedId((cur) => (cur === client.id ? null : client.id))
                    }
                    className="w-full text-left rounded-lg focus-visible:outline-none focus-visible:shadow-focus"
                    aria-pressed={selectedId === client.id}
                  >
                    <BlastRadiusBar
                      label={client.label}
                      score={score}
                      max={Math.max(maxBlast, 1)}
                      emphasised={client.id === topClientId && score > 0}
                    />
                  </button>
                </li>
              ))}
            </ul>
          )}

          {selected && (
            <div className="glass-soft rounded-lg p-4 flex flex-col gap-3 animate-fade-up">
              <div className="section-heading">{selected.client.label} · breakdown</div>
              {selectedBreakdown.length === 0 ? (
                <div className="text-caption text-sentinel-text-tertiary">
                  No reachable servers.
                </div>
              ) : (
                <ul className="flex flex-col gap-2">
                  {selectedBreakdown.map((row) => (
                    <li
                      key={row.name}
                      className="flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="text-body text-sentinel-text-primary truncate">
                          {row.name}
                        </div>
                        <div className="text-caption text-sentinel-text-tertiary truncate">
                          {row.scopes.join(' · ') || 'no declared scopes'}
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </aside>
      </section>
    </div>
  );
}

// Re-export the contract's DiscoveredClient so other agents can import from
// this page if they consume the same shape (per spec instruction).
export type { DiscoveredClient } from '../api/contract';

// ─── Local KPI tile (kept inline; the page is exclusive scope) ─────────────

interface KpiProps {
  label: string;
  value: number | string | null;
  emphasised?: boolean;
}

function Kpi({ label, value, emphasised }: KpiProps) {
  return (
    <div
      className={
        'card min-w-0 flex flex-col gap-3' +
        (emphasised ? ' border-sentinel-critical-border' : '')
      }
    >
      <div className="flex items-center justify-between gap-2">
        <div className="section-heading">{label}</div>
        {emphasised && (
          <span className="dot dot-critical" aria-hidden />
        )}
      </div>
      {value === null ? (
        <div className="skeleton h-8 w-20" />
      ) : (
        <div className="text-metric-lg tabular-nums text-sentinel-text-primary">
          {value}
        </div>
      )}
    </div>
  );
}

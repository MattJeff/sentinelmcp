// OverviewPage — high-level snapshot of MCP exposure.
// Built by agent UI-1. Glass + aurora. Data via SWR + api.* wrapper.

import { useEffect } from 'react';
import useSWR, { useSWRConfig } from 'swr';

import { api, onLiveTick } from '../api/tauri';
import type {
  ComplianceReference,
  DiscoveryReport,
  ExecutiveSummary,
  Finding,
  ScanProgress,
  ServerCard,
} from '../api/contract';

import Hero from './Overview/Hero';
import RecentFindings from './Overview/RecentFindings';

// SWR keys are centralised so the Refresh button can re-validate every tile.
const SWR_KEYS = [
  'executiveSummary',
  'listFindings',
  'complianceReferences',
  'listServers',
  'scanProgress',
  'discoverSystem',
] as const;

export default function OverviewPage() {
  const { mutate } = useSWRConfig();

  const summary = useSWR<ExecutiveSummary>('executiveSummary', () =>
    api.executiveSummary(),
  );
  const findings = useSWR<Finding[]>('listFindings', () => api.listFindings());
  const compliance = useSWR<ComplianceReference[]>('complianceReferences', () =>
    api.complianceReferences(),
  );
  const servers = useSWR<ServerCard[]>('listServers', () => api.listServers());
  const scan = useSWR<ScanProgress>('scanProgress', () => api.scanProgress());
  const discovery = useSWR<DiscoveryReport>('discoverSystem', () =>
    api.discoverSystem(),
  );

  const firstError =
    summary.error ??
    findings.error ??
    compliance.error ??
    discovery.error ??
    null;

  const serverEndpointById: Record<string, string> = {};
  for (const s of servers.data ?? []) {
    serverEndpointById[s.id] = s.endpoint;
  }

  // ─── KPI derivations from live data ──────────────────────────────────────
  // "Servers detected" = distinct MCP servers in the canonical inventory — the
  // SAME source as Inventory, Approvals and the signed Report (the store, keyed
  // by canonical identity package_id+scope). Discovery may DECLARE more (e.g.
  // 12) because configs list duplicates by identity and unreachable entries;
  // those are merged/dropped here, so this matches the report (e.g. 9) instead
  // of contradicting it.
  const serversDetected = servers.data ? servers.data.length : null;

  const allFindings = findings.data ?? null;
  const atRisk =
    allFindings === null
      ? null
      : allFindings.filter(
          (f) => f.severity === 'high' || f.severity === 'critical',
        ).length;
  const critical =
    allFindings === null
      ? null
      : allFindings.filter((f) => f.severity === 'critical').length;

  const ttfr = scan.data?.time_to_first_red_ms ?? null;

  // Sort findings by timestamp desc, then keep the most recent five.
  const recent = (allFindings ?? [])
    .slice()
    .sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
    .slice(0, 5);

  const heroLoading =
    servers.isLoading || findings.isLoading || scan.isLoading;

  function refreshAll() {
    for (const key of SWR_KEYS) {
      void mutate(key);
    }
  }

  // Live background loop: revalidate every Overview tile whenever the
  // background scan completes, so KPIs stay in sync without polling.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const off = await onLiveTick(() => {
        for (const key of SWR_KEYS) {
          void mutate(key);
        }
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [mutate]);

  return (
    <div className="w-full max-w-[1400px] mx-auto space-y-8">
      {/* Page actions — the layout titlebar already carries the page title. */}
      <div className="flex items-center justify-end">
        <button type="button" className="btn" onClick={refreshAll}>
          Refresh
        </button>
      </div>

      {firstError && (
        <div
          role="alert"
          className="flex items-center gap-3 rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-body text-sentinel-critical"
        >
          <span className="dot dot-critical" aria-hidden="true" />
          <span className="min-w-0 truncate">
            {String((firstError as Error)?.message ?? firstError)}
          </span>
        </div>
      )}

      {/* Row 1 — Hero KPIs */}
      <section aria-label="Key metrics">
        <Hero
          serversDetected={serversDetected}
          atRisk={atRisk}
          critical={critical}
          timeToFirstRedMs={ttfr}
          isLoading={heroLoading}
        />
      </section>

      {/* Row 2 — Activity (2/3) + Compliance (1/3) */}
      <section className="grid gap-4 grid-cols-1 lg:grid-cols-3">
        <div className="card lg:col-span-2 flex flex-col gap-6 min-w-0">
          <div className="flex items-baseline justify-between gap-4">
            <h2 className="text-title text-sentinel-text-primary">
              Recent findings
            </h2>
            <div className="section-heading shrink-0">Last 5</div>
          </div>
          <RecentFindings
            findings={recent}
            serverEndpointById={serverEndpointById}
            isLoading={findings.isLoading}
          />
        </div>

        <div className="card flex flex-col gap-6 min-w-0">
          <div className="flex items-baseline justify-between gap-4">
            <h2 className="text-title text-sentinel-text-primary">
              Compliance snapshot
            </h2>
            <div className="section-heading shrink-0">Coverage</div>
          </div>
          <ComplianceSnapshot
            references={compliance.data}
            isLoading={compliance.isLoading}
          />
        </div>
      </section>
    </div>
  );
}

// ─── Compliance snapshot (small, kept inline) ──────────────────────────────

interface ComplianceSnapshotProps {
  references: ComplianceReference[] | undefined;
  isLoading: boolean;
}

const STATIC_FRAMEWORKS: ComplianceReference[] = [
  { framework: 'SOC 2', identifier: 'SOC 2', title: 'Trust Services Criteria', url: null },
  { framework: 'ISO 27001', identifier: 'ISO 27001', title: 'ISMS controls', url: null },
];

function ComplianceSnapshot({ references, isLoading }: ComplianceSnapshotProps) {
  if (isLoading) {
    return (
      <div className="flex flex-col gap-2">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="skeleton h-10 w-full" />
        ))}
      </div>
    );
  }

  // Merge the backend-provided references with two static frameworks
  // (SOC 2 / ISO 27001) that the contract guarantees we should always show.
  const merged = [...(references ?? []), ...STATIC_FRAMEWORKS];
  const seen = new Set<string>();
  const unique = merged.filter((r) => {
    const key = `${r.framework}::${r.identifier}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return (
    <ul className="flex flex-col gap-2">
      {unique.map((r) => (
        <li
          key={`${r.framework}-${r.identifier}`}
          className="flex items-center gap-3 rounded-lg border border-sentinel-border-soft bg-white/3 px-3 py-2 transition-colors duration-150 hover:bg-sentinel-raised hover:border-sentinel-border-strong"
        >
          <span className="badge badge-accent font-mono shrink-0">
            {r.identifier}
          </span>
          <div className="flex-1 min-w-0">
            <div className="text-body font-medium text-sentinel-text-primary truncate">
              {r.title}
            </div>
            <div className="text-caption text-sentinel-text-tertiary truncate">
              {r.framework}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

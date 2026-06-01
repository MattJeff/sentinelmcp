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
  // "Servers detected" = sum of every declared server across discovered clients.
  const serversDetected =
    discovery.data?.clients.reduce(
      (acc, c) => acc + (c.servers?.length ?? 0),
      0,
    ) ?? null;

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
    discovery.isLoading || findings.isLoading || scan.isLoading;

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
    <div className="flex flex-col gap-6 w-full max-w-[1600px] mx-auto">
      <div className="flex items-center justify-between animate-fade-up">
        <h1 className="text-[18px] font-semibold tracking-tight text-sentinel-text-primary">
          Overview
        </h1>
        <button type="button" className="btn" onClick={refreshAll}>
          Refresh
        </button>
      </div>

      {firstError && (
        <div className="animate-fade-up">
          <span className="pill pill-red">
            <span className="dot dot-red" />
            {String((firstError as Error)?.message ?? firstError)}
          </span>
        </div>
      )}

      {/* Row 1 — Hero KPIs */}
      <section className="animate-fade-up">
        <Hero
          serversDetected={serversDetected}
          atRisk={atRisk}
          critical={critical}
          timeToFirstRedMs={ttfr}
          isLoading={heroLoading}
        />
      </section>

      {/* Row 2 — Activity (2/3) + Compliance (1/3) */}
      <section className="grid gap-4 grid-cols-1 lg:grid-cols-3 animate-fade-up">
        <div className="card lg:col-span-2 flex flex-col gap-4 min-w-0">
          <div className="flex items-center justify-between">
            <h2 className="text-[15px] font-semibold tracking-tight text-sentinel-text-primary">
              Recent findings
            </h2>
            <div className="section-heading">Last 5</div>
          </div>
          <RecentFindings
            findings={recent}
            serverEndpointById={serverEndpointById}
            isLoading={findings.isLoading}
          />
        </div>

        <div className="card flex flex-col gap-4 min-w-0">
          <div className="flex items-center justify-between">
            <h2 className="text-[15px] font-semibold tracking-tight text-sentinel-text-primary">
              Compliance snapshot
            </h2>
            <div className="section-heading">Coverage</div>
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
          className="flex items-center gap-3 rounded-lg px-3 py-2 bg-white/5"
        >
          <span className="pill pill-blue font-mono text-[10px]">
            {r.identifier}
          </span>
          <div className="flex-1 min-w-0">
            <div className="text-[12px] font-medium text-sentinel-text-primary truncate">
              {r.title}
            </div>
            <div className="text-[10px] text-sentinel-text-tertiary truncate">
              {r.framework}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

// Compliance page — audit-ready coverage map of MCP security frameworks.
// Implemented by Agent UI-6, wired by Agent W12.

import { useMemo, useState } from 'react';
import useSWR, { useSWRConfig } from 'swr';
import {
  FileSignature,
  ChevronDown,
  Search,
  Loader2,
  CheckCircle2,
  AlertCircle,
  MinusCircle,
} from 'lucide-react';

import { api } from '../api/tauri';
import type {
  ComplianceCoverage,
  ComplianceCoverageRow,
  ComplianceReference,
  Finding,
  ReportBundle,
} from '../api/contract';
import ComplianceFramework, {
  type ComplianceBadgeColor,
} from '../components/ComplianceFramework';
import {
  CategoryBadge,
  ComplianceRefBadges,
} from '../lib/findingCategory';
import { useToastStore } from '../hooks/useToast';

export interface CompliancePageProps {
  /** Optional handler so the parent shell can navigate to the report page. */
  onGenerateReport?: () => void;
  /** Called after a report has been successfully generated. */
  onGenerated?: (bundle: ReportBundle) => void;
}

interface FrameworkSpec {
  label: string;
  badge: ComplianceBadgeColor;
  description: string;
  // The framework strings emitted by the backend that map to this tile.
  aliases: string[];
}

const FRAMEWORKS: FrameworkSpec[] = [
  {
    label: 'OWASP MCP',
    badge: 'purple',
    description:
      'Top risks specific to Model Context Protocol servers, tools and prompts.',
    aliases: ['OWASP MCP', 'OWASP-MCP', 'OWASP'],
  },
  {
    label: 'SAFE-MCP',
    badge: 'blue',
    description:
      'Behavioural threat taxonomy for MCP — poisoning, rug-pulls and exfiltration.',
    aliases: ['SAFE-MCP', 'SAFE'],
  },
  {
    label: 'SOC 2',
    badge: 'green',
    description:
      'Trust services criteria — security, availability and confidentiality controls.',
    aliases: ['SOC 2', 'SOC2', 'SOC-2'],
  },
  {
    label: 'ISO 27001',
    badge: 'orange',
    description:
      'Information security management system controls relevant to AI supply chain.',
    aliases: ['ISO 27001', 'ISO27001', 'ISO-27001', 'ISO/IEC 27001'],
  },
];

function normalize(s: string): string {
  return s.trim().toLowerCase().replace(/[\s_\-/]+/g, '');
}

function frameworkMatcher(spec: FrameworkSpec): (raw: string) => boolean {
  const keys = new Set(spec.aliases.map(normalize));
  return (raw: string) => keys.has(normalize(raw));
}

// Visual treatment for one coverage level. The matrix is "honesty-first": a
// dedicated detector reads "Covered", a heuristic/indirect signal "Partial",
// and an assumed blind spot "Not covered". Tints reuse the calm severity
// tokens (ok / medium / neutral) so a RSSI parses it at a glance.
type CoverageLevelMeta = {
  label: string;
  badgeClass: string;
  Icon: typeof CheckCircle2;
  iconClass: string;
};

function coverageLevelMeta(level: string): CoverageLevelMeta {
  switch (level) {
    case 'yes':
      return {
        label: 'Covered',
        badgeClass: 'badge-ok',
        Icon: CheckCircle2,
        iconClass: 'text-sentinel-ok',
      };
    case 'partial':
      return {
        label: 'Partial',
        badgeClass: 'badge-medium',
        Icon: AlertCircle,
        iconClass: 'text-sentinel-medium',
      };
    default:
      return {
        label: 'Not covered',
        badgeClass: 'badge-neutral',
        Icon: MinusCircle,
        iconClass: 'text-sentinel-text-tertiary',
      };
  }
}

export default function CompliancePage({
  onGenerateReport,
  onGenerated,
}: CompliancePageProps) {
  const { data: refs, isLoading: refsLoading } = useSWR<ComplianceReference[]>(
    'compliance_references',
    () => api.complianceReferences(),
  );
  const { data: findings, isLoading: findingsLoading } = useSWR<Finding[]>(
    'list_findings',
    () => api.listFindings(),
  );
  const pushToast = useToastStore((s) => s.push);
  const {
    data: coverage,
    isLoading: coverageLoading,
    error: coverageError,
  } = useSWR<ComplianceCoverage>(
    'compliance_coverage',
    () => api.complianceCoverage(),
    {
      onError: (err) => {
        pushToast({
          title: 'Coverage matrix failed to load',
          description: err instanceof Error ? err.message : String(err),
          severity: 'high',
        });
      },
    },
  );
  const { mutate } = useSWRConfig();

  const isLoading = refsLoading || findingsLoading;

  const [query, setQuery] = useState('');
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [genSuccess, setGenSuccess] = useState(false);

  async function handleGenerate() {
    if (generating) return;
    setGenError(null);
    setGenSuccess(false);
    setGenerating(true);
    try {
      const bundle = await mutate<ReportBundle>(
        'generate_report',
        () => api.generateReport(),
        { revalidate: false, populateCache: true },
      );
      setGenSuccess(true);
      if (bundle) onGenerated?.(bundle);
      // Also forward to the legacy navigation handler if the parent provided one.
      onGenerateReport?.();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setGenError(msg || 'Report generation failed');
    } finally {
      setGenerating(false);
    }
  }

  // For each tile: gather its references + count findings whose
  // compliance_refs[] mentions any of its identifiers.
  const tiles = useMemo(() => {
    const allRefs = refs ?? [];
    const allFindings = findings ?? [];

    return FRAMEWORKS.map((spec) => {
      const matches = frameworkMatcher(spec);
      const tileRefs = allRefs.filter((r) => matches(r.framework));
      const identifierSet = new Set(tileRefs.map((r) => r.identifier));

      let findingsCount = 0;
      let hasCritical = false;
      for (const f of allFindings) {
        const hit = f.compliance_refs.some((ref) => {
          // A compliance_ref string may be either an identifier (e.g. "MCP09")
          // or a "framework:identifier" pair. Try both.
          if (identifierSet.has(ref)) return true;
          const [maybeFramework, maybeId] = ref.split(/[:#/]/, 2);
          if (
            maybeFramework &&
            maybeId &&
            matches(maybeFramework) &&
            identifierSet.has(maybeId)
          ) {
            return true;
          }
          // Fallback: framework-only prefix.
          if (maybeFramework && matches(maybeFramework)) return true;
          return false;
        });
        if (hit) {
          findingsCount += 1;
          if (f.severity === 'critical') hasCritical = true;
        }
      }

      return {
        spec,
        references: tileRefs,
        findingsCount,
        hasCritical,
      };
    });
  }, [refs, findings]);

  // Filter tiles + their references by the search query.
  const filteredTiles = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return tiles;
    return tiles
      .map((tile) => {
        const frameworkHit = tile.spec.label.toLowerCase().includes(q);
        const matchedRefs = tile.references.filter(
          (r) =>
            r.identifier.toLowerCase().includes(q) ||
            r.title.toLowerCase().includes(q),
        );
        if (frameworkHit) {
          // Framework label matches → keep all references.
          return tile;
        }
        if (matchedRefs.length === 0) return null;
        return { ...tile, references: matchedRefs };
      })
      .filter((t): t is (typeof tiles)[number] => t !== null);
  }, [tiles, query]);

  // Coverage matrix rows, filtered by the same search box and grouped by
  // framework so the table reads as "OWASP MCP …", "OWASP ASI …" blocks.
  const coverageGroups = useMemo(() => {
    const rows = coverage?.matrix ?? [];
    const q = query.trim().toLowerCase();
    const filtered = q
      ? rows.filter((r) =>
          [r.framework, r.identifier, r.title, r.justification].some((s) =>
            (s ?? '').toLowerCase().includes(q),
          ),
        )
      : rows;
    const groups = new Map<string, ComplianceCoverageRow[]>();
    for (const row of filtered) {
      const list = groups.get(row.framework) ?? [];
      list.push(row);
      groups.set(row.framework, list);
    }
    return Array.from(groups.entries());
  }, [coverage, query]);

  // Findings that actually carry framework references — so a RSSI can see the
  // SAFE-MCP / OWASP / ASI / ATT&CK badges attached to each concrete signal.
  const mappedFindings = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (findings ?? []).filter((f) => {
      if (f.compliance_refs.length === 0) return false;
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        f.compliance_refs.some((r) => r.toLowerCase().includes(q))
      );
    });
  }, [findings, query]);

  return (
    <div className="animate-fade-up mx-auto w-full max-w-[1400px] flex flex-col gap-8">
      {/* Hero panel */}
      <section className="surface rounded-glass p-8 flex flex-col gap-6 min-[900px]:flex-row min-[900px]:items-center min-[900px]:justify-between">
        <div className="flex-1 min-w-0">
          <div className="section-heading mb-2">Compliance</div>
          <h1 className="text-metric-lg text-sentinel-text-primary">
            Audit-ready compliance map
          </h1>
          <p className="text-body text-sentinel-text-secondary mt-2 max-w-2xl">
            Every MCP finding is mapped to recognised frameworks so you can hand
            auditors a signed report instead of a screenshot.
          </p>
        </div>
        <div className="flex flex-col items-stretch gap-2 shrink-0 min-[900px]:items-end">
          <button
            type="button"
            className="btn btn-primary no-drag"
            onClick={() => {
              void handleGenerate();
            }}
            disabled={generating}
            aria-busy={generating}
          >
            {generating ? (
              <Loader2 size={16} aria-hidden className="animate-spin" />
            ) : (
              <FileSignature size={16} aria-hidden />
            )}
            {generating ? 'Generating…' : 'Generate signed report'}
          </button>
          {genSuccess && !genError && (
            <div
              role="status"
              className="flex items-center gap-2 text-caption text-sentinel-ok"
            >
              <CheckCircle2 size={12} aria-hidden />
              <span>
                Report ready —{' '}
                <button
                  type="button"
                  className="underline underline-offset-2 transition-colors duration-150 hover:text-sentinel-text-primary focus-visible:outline-none focus-visible:shadow-focus rounded-lg"
                  onClick={() => onGenerateReport?.()}
                >
                  open Report page
                </button>
              </span>
            </div>
          )}
          {genError && (
            <div
              role="alert"
              className="flex items-center gap-2 text-caption text-sentinel-critical"
            >
              <AlertCircle size={12} aria-hidden />
              <span>{genError}</span>
            </div>
          )}
        </div>
      </section>

      {/* Search filter */}
      <div className="relative">
        <Search
          size={14}
          aria-hidden
          className="absolute left-3 top-1/2 -translate-y-1/2 text-sentinel-text-tertiary pointer-events-none"
        />
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter by framework or control identifier (e.g. MCP09, SAFE)"
          className="input pl-9"
          aria-label="Filter compliance frameworks"
        />
      </div>

      {/* Framework grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="card" aria-hidden>
              <div className="skeleton h-4 w-2/3 mb-3" />
              <div className="skeleton h-3 w-1/2 mb-2" />
              <div className="skeleton h-3 w-1/3 mb-4" />
              <div className="skeleton h-3 w-full mb-2" />
              <div className="skeleton h-3 w-5/6 mb-2" />
              <div className="skeleton h-3 w-4/6" />
            </div>
          ))}
        </div>
      ) : filteredTiles.length === 0 ? (
        <div className="surface rounded-glass px-8 py-12 text-center text-body text-sentinel-text-secondary">
          No framework or control matches{' '}
          <span className="font-mono text-caption text-sentinel-text-primary">
            “{query}”
          </span>
          .
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {filteredTiles.map(
            ({ spec, references, findingsCount, hasCritical }) => (
              <ComplianceFramework
                key={spec.label}
                frameworkLabel={spec.label}
                badgeColor={spec.badge}
                description={spec.description}
                references={references}
                findingsCount={findingsCount}
                hasCritical={hasCritical}
              />
            ),
          )}
        </div>
      )}

      {/* Coverage matrix — honesty-first OWASP MCP / ASI coverage for a RSSI */}
      <section className="surface rounded-glass p-6 flex flex-col gap-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="section-heading mb-1">Detection coverage</div>
            <h2 className="text-title text-sentinel-text-primary">
              OWASP MCP &amp; ASI coverage matrix
            </h2>
            <p className="text-caption text-sentinel-text-secondary mt-1 max-w-2xl">
              What Sentinel actually detects, where it is partial, and the blind
              spots we own up to — per attack category.
            </p>
          </div>
          {coverage && (
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <span className="badge badge-ok tabular-nums" title="Categories with a dedicated detector">
                <CheckCircle2 size={11} aria-hidden />
                {coverage.covered} covered
              </span>
              <span className="badge badge-medium tabular-nums" title="Categories caught indirectly / heuristically">
                <AlertCircle size={11} aria-hidden />
                {coverage.partial} partial
              </span>
              <span className="badge badge-neutral tabular-nums" title="Categories out of scope for now">
                <MinusCircle size={11} aria-hidden />
                {coverage.not_covered} not covered
              </span>
              <span
                className="pill pill-tertiary font-mono"
                title="Version tag of the coverage table"
              >
                {coverage.version}
              </span>
            </div>
          )}
        </div>

        {coverageLoading ? (
          <div className="flex flex-col gap-3" aria-hidden>
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className="skeleton h-4 w-4 rounded-full" />
                <div className="flex-1">
                  <div className="skeleton h-3 w-1/3 mb-2" />
                  <div className="skeleton h-3 w-2/3" />
                </div>
              </div>
            ))}
          </div>
        ) : coverageError && !coverage ? (
          <div
            role="alert"
            className="flex items-center gap-2 rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-caption text-sentinel-critical"
          >
            <AlertCircle size={14} aria-hidden />
            Coverage matrix unavailable.
          </div>
        ) : coverageGroups.length === 0 ? (
          <div className="rounded-lg border border-dashed border-sentinel-border-soft px-4 py-6 text-center text-caption text-sentinel-text-tertiary">
            {query.trim()
              ? `No coverage row matches “${query}”.`
              : 'No coverage data available.'}
          </div>
        ) : (
          <div className="flex flex-col gap-6">
            {coverageGroups.map(([framework, rows]) => (
              <div key={framework}>
                <div className="section-heading mb-2">{framework}</div>
                <ul className="flex flex-col">
                  {rows.map((row, idx) => {
                    const meta = coverageLevelMeta(row.level);
                    const isLast = idx === rows.length - 1;
                    return (
                      <li
                        key={`${row.identifier}-${idx}`}
                        className={
                          isLast
                            ? 'flex items-start gap-3 py-3'
                            : 'flex items-start gap-3 py-3 border-b border-sentinel-border-soft'
                        }
                      >
                        <meta.Icon
                          size={15}
                          aria-hidden
                          className={`mt-0.5 shrink-0 ${meta.iconClass}`}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-caption font-semibold text-sentinel-text-primary">
                              {row.identifier}
                            </span>
                            <span className="text-caption text-sentinel-text-secondary">
                              {row.title}
                            </span>
                            <span className={`badge ${meta.badgeClass} ml-auto`}>
                              {meta.label}
                            </span>
                          </div>
                          <p className="text-caption text-sentinel-text-tertiary mt-1 leading-relaxed">
                            {row.justification}
                          </p>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Findings mapped to controls — per-finding framework badges */}
      <section className="surface rounded-glass p-6 flex flex-col gap-4">
        <div className="flex items-center justify-between gap-3">
          <div className="section-heading">Findings mapped to controls</div>
          <span className="badge badge-neutral tabular-nums">
            {mappedFindings.length}
          </span>
        </div>
        {findingsLoading ? (
          <div className="flex flex-col gap-3" aria-hidden>
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="skeleton h-10 w-full rounded-lg" />
            ))}
          </div>
        ) : mappedFindings.length === 0 ? (
          <div className="rounded-lg border border-dashed border-sentinel-border-soft px-4 py-6 text-center text-caption text-sentinel-text-tertiary">
            No open finding carries a framework reference yet.
          </div>
        ) : (
          <ul className="flex flex-col gap-3">
            {mappedFindings.map((f) => (
              <li
                key={f.id}
                className="rounded-lg border border-sentinel-border bg-sentinel-inset p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <CategoryBadge
                    severity={f.severity}
                    finding_type={f.finding_type}
                    title={f.title}
                    detail={f.detail}
                    diff={f.diff}
                    compliance_refs={f.compliance_refs}
                  />
                  <span className="text-caption font-semibold text-sentinel-text-primary">
                    {f.title}
                  </span>
                </div>
                <ComplianceRefBadges refs={f.compliance_refs} className="mt-2" />
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* "How we map" disclosure */}
      <details className="surface rounded-glass p-6 group">
        <summary className="flex items-center justify-between gap-4 cursor-pointer list-none rounded-lg focus-visible:outline-none focus-visible:shadow-focus">
          <div>
            <div className="section-heading mb-1">Methodology</div>
            <div className="text-title text-sentinel-text-primary">
              How we map findings to controls
            </div>
          </div>
          <ChevronDown
            size={16}
            aria-hidden
            className="shrink-0 text-sentinel-text-tertiary transition-transform duration-200 group-open:rotate-180"
          />
        </summary>
        <p className="text-body text-sentinel-text-secondary leading-relaxed mt-4 max-w-3xl">
          Every detector emits a finding with one or more{' '}
          <span className="font-mono text-caption text-sentinel-text-primary">
            compliance_refs
          </span>{' '}
          such as <span className="font-mono text-caption">MCP09</span> or{' '}
          <span className="font-mono text-caption">SAFE-T1201</span>. Each
          identifier is matched against the canonical control catalogue shipped
          with Sentinel, then grouped under its framework. SOC 2 and ISO 27001
          mappings are derived from the underlying MCP / SAFE-MCP control so a
          single behavioural signal can satisfy multiple audits at once.
        </p>
      </details>
    </div>
  );
}

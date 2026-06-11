// Compliance page — audit-ready coverage map of MCP security frameworks.
// Implemented by Agent UI-6, wired by Agent W12.

import { useMemo, useState } from 'react';
import useSWR, { useSWRConfig } from 'swr';
import { FileSignature, ChevronDown, Search, Loader2, CheckCircle2, AlertCircle } from 'lucide-react';

import { api } from '../api/tauri';
import type { ComplianceReference, Finding, ReportBundle } from '../api/contract';
import ComplianceFramework, {
  type ComplianceBadgeColor,
} from '../components/ComplianceFramework';

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

// ReportPage — signed compliance bundle viewer.
// Implemented by Agent UI-7.
//
// The page renders the auditor-facing report. It calls api.generateReport()
// through SWR (manual mutation only) and surfaces the resulting markdown in
// Radix tabs. When the bundle is signed, an Ed25519 ribbon is shown; when
// not, a draft pill is shown instead.

import { useState } from 'react';
import useSWR from 'swr';
import * as Tabs from '@radix-ui/react-tabs';
import {
  ChevronDown,
  FileText,
  FileJson,
  Lock,
  Share2,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';

import { api } from '../api/tauri';
import type { ReportBundle } from '../api/contract';
import MarkdownView from '../components/MarkdownView';
import { useToastStore } from '../hooks/useToast';

const SWR_KEY = 'generate_report';

const TABS = [
  { id: 'executive', label: 'Executive summary', field: 'executive_summary_md' },
  { id: 'inventory', label: 'Inventory', field: 'inventory_md' },
  { id: 'changelog', label: 'Changelog', field: 'changelog_md' },
  { id: 'compliance', label: 'Compliance', field: 'compliance_map_md' },
  { id: 'remediation', label: 'Remediation', field: 'remediation_plan_md' },
] as const;

type TabId = (typeof TABS)[number]['id'];

function formatTimestamp(iso: string | null): string {
  if (!iso) return '';
  // Render the raw ISO timestamp — auditors expect the exact value the
  // signature was bound to, so we do not localize it.
  return iso;
}

function basename(path: string): string {
  // Tolerate both POSIX and Windows separators since the backend hands us
  // whatever the host filesystem produced.
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

export default function ReportPage() {
  const [activeTab, setActiveTab] = useState<TabId>('executive');
  const [generating, setGenerating] = useState(false);
  const [openingPath, setOpeningPath] = useState<string | null>(null);
  const [exportingStix, setExportingStix] = useState(false);
  const pushToast = useToastStore((s) => s.push);

  // SWR cache only — we never fetch on mount; bundle generation is explicit.
  const { data, mutate } = useSWR<ReportBundle | null>(SWR_KEY, null, {
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
    revalidateIfStale: false,
    fallbackData: null,
  });

  const bundle = data ?? null;
  const hasBundle = bundle !== null;

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const next = await api.generateReport();
      await mutate(next, { revalidate: false });
      pushToast({
        title: hasBundle ? 'Report bundle regenerated' : 'Report bundle generated',
        description: 'Signed PDF + JSON ready — open them from the buttons above.',
        severity: 'info',
      });
    } catch (err) {
      pushToast({
        title: 'Report generation failed',
        description: err instanceof Error ? err.message : String(err),
        severity: 'high',
      });
    } finally {
      setGenerating(false);
    }
  };

  const handleOpen = async (path: string | null) => {
    if (!path) return;
    setOpeningPath(path);
    try {
      await api.openReportFile(path);
    } finally {
      setOpeningPath(null);
    }
  };

  // Export a STIX 2.1 bundle of the current Sentinel state, then reveal the
  // resulting `.stix.json` file in the system file browser. Errors are
  // surfaced through the global toast store so the user gets actionable
  // feedback even when the Tauri command fails (e.g. permission denied).
  const handleExportStix = async () => {
    setExportingStix(true);
    try {
      const path = await api.stixExportBundle();
      // Reuse the existing "open in Finder" path so STIX bundles behave
      // exactly like the PDF/JSON artefacts: the OS picks a sensible
      // default (Finder reveal on macOS, Explorer on Windows).
      await api.openReportFile(path);
      pushToast({
        title: `STIX bundle exported to ${basename(path)}`,
        description: path,
        severity: 'info',
      });
    } catch (err) {
      pushToast({
        title: 'STIX export failed',
        description: err instanceof Error ? err.message : String(err),
        severity: 'high',
      });
    } finally {
      setExportingStix(false);
    }
  };

  return (
    <div className="animate-fade-up mx-auto w-full max-w-[1400px] space-y-8">
      {/* ── Hero ────────────────────────────────────────────────────────── */}
      <section className="surface rounded-glass p-6">
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 md:gap-6">
          <div className="min-w-0">
            <div className="section-heading mb-2 flex items-center gap-2">
              <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
              Signed report
            </div>
            <h1 className="text-metric-lg text-sentinel-text-primary">
              Compliance bundle
            </h1>
            <p className="mt-2 text-body text-sentinel-text-secondary max-w-2xl">
              Signed Ed25519 · OWASP MCP09/MCP03 · SAFE-MCP T1001/T1201 · SOC 2 · ISO 27001
            </p>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:flex-wrap no-drag">
            {!hasBundle ? (
              <button
                type="button"
                className="btn btn-primary"
                disabled={generating}
                onClick={handleGenerate}
              >
                {generating ? (
                  <>
                    <span className="skeleton h-3 w-3 rounded-full" />
                    Generating bundle…
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    Generate signed bundle
                  </>
                )}
              </button>
            ) : (
              <>
                <button
                  type="button"
                  className="btn"
                  disabled={!bundle?.pdf_path || openingPath === bundle?.pdf_path}
                  onClick={() => handleOpen(bundle?.pdf_path ?? null)}
                >
                  <FileText className="w-4 h-4" />
                  Open PDF
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={!bundle?.json_path || openingPath === bundle?.json_path}
                  onClick={() => handleOpen(bundle?.json_path ?? null)}
                >
                  <FileJson className="w-4 h-4" />
                  Open JSON
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={exportingStix}
                  onClick={handleExportStix}
                >
                  {exportingStix ? (
                    <>
                      <span className="skeleton h-3 w-3 rounded-full" />
                      Exporting…
                    </>
                  ) : (
                    <>
                      <Share2 className="w-4 h-4" />
                      Export STIX bundle
                    </>
                  )}
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={generating}
                  onClick={handleGenerate}
                >
                  {generating ? (
                    <>
                      <span className="skeleton h-3 w-3 rounded-full" />
                      Regenerating…
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      Regenerate bundle
                    </>
                  )}
                </button>
              </>
            )}
          </div>
        </div>
      </section>

      {/* ── Tabs ─────────────────────────────────────────────────────────── */}
      <Tabs.Root
        value={activeTab}
        onValueChange={(v) => setActiveTab(v as TabId)}
      >
        <div className="-mx-1 overflow-x-auto px-1">
        <Tabs.List
          className="glass-soft rounded-pill inline-flex items-center gap-1 p-1 max-w-full whitespace-nowrap"
          aria-label="Report sections"
        >
          {TABS.map((tab) => (
            <Tabs.Trigger
              key={tab.id}
              value={tab.id}
              disabled={!hasBundle}
              className={[
                'rounded-pill px-4 py-1.5 text-caption font-medium transition-colors duration-150',
                'text-sentinel-text-secondary hover:text-sentinel-text-primary',
                'focus-visible:outline-none focus-visible:shadow-focus',
                'data-[state=active]:bg-sentinel-raised data-[state=active]:text-sentinel-text-primary',
                'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-sentinel-text-secondary',
              ].join(' ')}
            >
              {tab.label}
            </Tabs.Trigger>
          ))}
        </Tabs.List>
        </div>

        <div className="surface rounded-glass p-6 mt-4 min-h-[280px] overflow-x-auto min-w-0">
          {!hasBundle ? (
            <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
              <FileText className="w-6 h-6 text-sentinel-text-faint" aria-hidden="true" />
              <div className="text-body text-sentinel-text-tertiary">
                Generate a bundle to see the report.
              </div>
            </div>
          ) : (
            TABS.map((tab) => (
              <Tabs.Content
                key={tab.id}
                value={tab.id}
                className="animate-fade-up focus:outline-none"
              >
                <MarkdownView source={(bundle as ReportBundle)[tab.field] ?? ''} />
              </Tabs.Content>
            ))
          )}
        </div>
      </Tabs.Root>

      {/* ── Signature strip ──────────────────────────────────────────────── */}
      <section>
        {hasBundle && bundle?.signed ? (
          <div
            className="flex items-center gap-3 rounded-glass border border-sentinel-ok-border bg-sentinel-ok-bg px-6 py-4 text-body font-medium text-sentinel-ok"
            role="status"
          >
            <Lock className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span>
              Signed at{' '}
              <span className="font-mono text-caption tabular-nums">
                {formatTimestamp(bundle.signature_iso8601)}
              </span>{' '}
              · Ed25519
            </span>
          </div>
        ) : hasBundle ? (
          <div className="inline-flex" role="status">
            <span className="badge badge-medium">
              <span className="dot dot-medium" aria-hidden="true" />
              Draft — not signed yet
            </span>
          </div>
        ) : null}
      </section>

      {/* ── Bundle paths disclosure ──────────────────────────────────────── */}
      {hasBundle && (
        <section>
          <details className="group glass-soft rounded-glass p-4 text-body no-drag">
            <summary className="flex items-center gap-2 cursor-pointer list-none rounded-lg text-sentinel-text-secondary hover:text-sentinel-text-primary transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus">
              <ChevronDown
                className="w-3.5 h-3.5 transition-transform group-open:rotate-0 -rotate-90"
                aria-hidden="true"
              />
              View bundle paths
            </summary>
            <div className="mt-4 space-y-2 pl-6">
              <div className="flex items-baseline gap-3">
                <span className="text-overline uppercase text-sentinel-text-tertiary w-12 shrink-0">
                  PDF
                </span>
                <span className="font-mono text-caption text-sentinel-text-secondary break-all">
                  {bundle?.pdf_path ?? '—'}
                </span>
              </div>
              <div className="flex items-baseline gap-3">
                <span className="text-overline uppercase text-sentinel-text-tertiary w-12 shrink-0">
                  JSON
                </span>
                <span className="font-mono text-caption text-sentinel-text-secondary break-all">
                  {bundle?.json_path ?? '—'}
                </span>
              </div>
            </div>
          </details>
        </section>
      )}
    </div>
  );
}

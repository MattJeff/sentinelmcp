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
      const { path } = await api.stixExportBundle();
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
    <div className="animate-fade-up space-y-6">
      {/* ── Hero ────────────────────────────────────────────────────────── */}
      <section className="glass rounded-glass p-6">
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 md:gap-6">
          <div className="min-w-0">
            <div className="section-heading mb-2 flex items-center gap-2">
              <ShieldCheck className="w-3.5 h-3.5" />
              Signed report
            </div>
            <h1 className="text-[28px] font-semibold tracking-tight text-sentinel-text-primary">
              Compliance bundle
            </h1>
            <p className="mt-2 text-[13px] text-sentinel-text-secondary max-w-2xl">
              Signed Ed25519 · OWASP MCP09/MCP03 · SAFE-MCP T1001/T1201 · SOC 2 · ISO 27001
            </p>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:flex-wrap no-drag">
            {!hasBundle ? (
              <button
                type="button"
                className="btn-primary btn"
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
                  className="btn-primary btn"
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
        <div className="-mx-1 overflow-x-auto">
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
                'rounded-pill px-3.5 py-1.5 text-[13px] font-medium transition-all duration-150',
                'text-sentinel-text-secondary hover:text-sentinel-text-primary',
                'data-[state=active]:bg-white/12 data-[state=active]:text-sentinel-text-primary',
                'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-sentinel-text-secondary',
              ].join(' ')}
            >
              {tab.label}
            </Tabs.Trigger>
          ))}
        </Tabs.List>
        </div>

        <div className="glass rounded-glass p-6 mt-4 min-h-[280px] overflow-x-auto min-w-0">
          {!hasBundle ? (
            <div className="text-[13px] text-sentinel-text-tertiary">
              Generate a bundle to see the report.
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
            className="flex items-center gap-3 rounded-glass px-5 py-3 text-[13px] font-medium"
            style={{
              background:
                'linear-gradient(90deg, rgba(52,199,89,0.18) 0%, rgba(52,199,89,0.08) 100%)',
              border: '1px solid rgba(52,199,89,0.40)',
              color: '#b8f5c8',
              boxShadow: '0 0 24px rgba(52,199,89,0.18)',
            }}
            role="status"
          >
            <Lock className="w-4 h-4" />
            <span>
              Signed at{' '}
              <span className="font-mono text-[12px]">
                {formatTimestamp(bundle.signature_iso8601)}
              </span>{' '}
              · Ed25519
            </span>
          </div>
        ) : hasBundle ? (
          <div className="inline-flex">
            <span className="pill pill-orange">
              <span className="dot dot-orange" />
              Draft — not signed yet
            </span>
          </div>
        ) : null}
      </section>

      {/* ── Bundle paths disclosure ──────────────────────────────────────── */}
      {hasBundle && (
        <section>
          <details className="group glass-soft rounded-glass px-4 py-3 text-[13px] no-drag">
            <summary className="flex items-center gap-2 cursor-pointer list-none text-sentinel-text-secondary hover:text-sentinel-text-primary transition-colors">
              <ChevronDown className="w-3.5 h-3.5 transition-transform group-open:rotate-0 -rotate-90" />
              View bundle paths
            </summary>
            <div className="mt-3 space-y-2 pl-5">
              <div className="flex items-baseline gap-2">
                <span className="text-[11px] uppercase tracking-wider text-sentinel-text-tertiary w-12 shrink-0">
                  PDF
                </span>
                <span className="font-mono text-[12px] text-sentinel-text-primary break-all">
                  {bundle?.pdf_path ?? '—'}
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-[11px] uppercase tracking-wider text-sentinel-text-tertiary w-12 shrink-0">
                  JSON
                </span>
                <span className="font-mono text-[12px] text-sentinel-text-primary break-all">
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

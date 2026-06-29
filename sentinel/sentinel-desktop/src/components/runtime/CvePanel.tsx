// CvePanel — known CVEs / supply-chain matches (Vague D).
//
// Confronts the declared inventory against the embedded MCP CVE database.
// Only stdio servers with a version pinned in their command line (`@org/pkg@1.2.3`)
// are checked, so an empty panel is the healthy common case rather than a gap.

import { useMemo } from 'react';
import useSWR from 'swr';
import { Bug, ExternalLink, Loader2, ShieldCheck } from 'lucide-react';

import { api } from '@/api/tauri';
import { COMMANDS, type CveFinding } from '@/api/contract';
import SeverityBadge, { severityRank } from './SeverityBadge';

/** Short, mono-friendly identity for a server UUID (first segment). */
function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

/** True when a reference string is a clickable URL rather than a bare CVE id. */
function isUrl(ref: string): boolean {
  return /^https?:\/\//i.test(ref);
}

export default function CvePanel() {
  const { data, isLoading, error } = useSWR<CveFinding[]>(
    COMMANDS.listCveFindings,
    api.listCveFindings,
    { revalidateOnFocus: false },
  );

  const findings = useMemo(
    () =>
      [...(data ?? [])].sort((a, b) => {
        const bySeverity = severityRank(b.severity) - severityRank(a.severity);
        return bySeverity !== 0 ? bySeverity : b.cvss - a.cvss;
      }),
    [data],
  );

  return (
    <section className="card flex flex-col gap-6" aria-label="Known CVEs">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-sentinel-border bg-sentinel-inset">
            <Bug className="h-4.5 w-4.5 text-sentinel-text-secondary" aria-hidden />
          </div>
          <div className="min-w-0">
            <h3 className="text-title text-sentinel-text-primary">Known CVEs</h3>
            <p className="mt-1 max-w-prose text-caption text-sentinel-text-secondary">
              A pinned dependency in your inventory matches a published
              vulnerability — upgrade it to a fixed version.
            </p>
          </div>
        </div>
        {data && findings.length > 0 && (
          <span className="badge badge-critical shrink-0 tabular-nums">
            {findings.length} match{findings.length === 1 ? '' : 'es'}
          </span>
        )}
      </div>

      {/* Body */}
      {error ? (
        <div
          className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-caption text-sentinel-critical"
          role="alert"
        >
          Failed to check the CVE database: {String(error)}
        </div>
      ) : isLoading && !data ? (
        <div className="flex items-center justify-center gap-2 py-8 text-caption text-sentinel-text-secondary">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          Checking pinned packages…
        </div>
      ) : findings.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-sentinel-border py-10 text-center">
          <ShieldCheck className="h-6 w-6 text-sentinel-ok" aria-hidden />
          <p className="text-body text-sentinel-text-secondary">No known CVEs</p>
          <p className="max-w-prose text-caption text-sentinel-text-tertiary">
            None of your pinned MCP packages match a vulnerability in the
            embedded database.
          </p>
        </div>
      ) : (
        <ul className="flex flex-col gap-2">
          {findings.map((f) => {
            const nvdUrl = `https://nvd.nist.gov/vuln/detail/${f.cve_id}`;
            return (
              <li
                key={`${f.server_id}-${f.cve_id}-${f.package}`}
                className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className="badge badge-neutral tabular-nums">
                    CVSS {f.cvss.toFixed(1)}
                  </span>
                  <a
                    href={nvdUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-caption text-sentinel-accent hover:underline focus-visible:outline-none focus-visible:shadow-focus rounded"
                  >
                    {f.cve_id}
                    <ExternalLink className="h-3 w-3" aria-hidden />
                  </a>
                  <span className="font-mono text-caption text-sentinel-text-primary">
                    {f.package}@{f.version}
                  </span>
                </div>
                <p className="mt-2 max-w-prose text-caption text-sentinel-text-secondary">
                  {f.summary}
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-caption text-sentinel-text-tertiary">
                  <span>
                    Affected:{' '}
                    <span className="font-mono text-sentinel-text-secondary">
                      {f.affected_range}
                    </span>
                  </span>
                  <span>
                    Server:{' '}
                    <span className="font-mono" title={f.server_id}>
                      {shortId(f.server_id)}
                    </span>
                  </span>
                </div>
                {f.references.filter(isUrl).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
                    {f.references.filter(isUrl).map((ref) => (
                      <a
                        key={ref}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-caption text-sentinel-accent hover:underline focus-visible:outline-none focus-visible:shadow-focus rounded"
                      >
                        {ref.replace(/^https?:\/\//i, '').split('/')[0]}
                        <ExternalLink className="h-3 w-3" aria-hidden />
                      </a>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

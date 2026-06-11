// Compliance framework tile — one frosted card per coverage framework.
// Implemented by Agent UI-6 for the Compliance page, wired by Agent W12.

import clsx from 'clsx';
import { ExternalLink } from 'lucide-react';

import { api } from '../api/tauri';

export type ComplianceBadgeColor = 'purple' | 'blue' | 'green' | 'orange';

export interface ComplianceFrameworkProps {
  frameworkLabel: string;
  badgeColor: ComplianceBadgeColor;
  description: string;
  references: { identifier: string; title: string; url: string | null }[];
  findingsCount: number;
  /** When true, color the footer pill red to surface critical mappings. */
  hasCritical?: boolean;
}

// Framework accents mapped onto the calm design tokens — severity colors stay
// reserved for findings; these are identity tints only.
const BADGE_CLASSES: Record<ComplianceBadgeColor, string> = {
  purple: 'text-sentinel-violet bg-sentinel-violet/10 border-sentinel-violet/25',
  blue: 'badge-accent',
  green: 'badge-ok',
  orange: 'badge-high',
};

// Open an external reference in the system browser. In Tauri this delegates
// to the `open_report_file` command (which uses tauri-plugin-opener and
// happily accepts HTTP URLs). In the Vite dev browser the mock returns
// `{ok:true}` without doing anything, so we fall back to `window.open`.
async function openExternal(url: string): Promise<void> {
  const hasTauri =
    typeof (window as unknown as { __TAURI_INTERNALS__?: unknown })
      .__TAURI_INTERNALS__ !== 'undefined';
  if (hasTauri) {
    try {
      await api.openReportFile(url);
      return;
    } catch {
      // Fall through to window.open.
    }
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}

export default function ComplianceFramework({
  frameworkLabel,
  badgeColor,
  description,
  references,
  findingsCount,
  hasCritical = false,
}: ComplianceFrameworkProps) {
  const badgeClass = hasCritical
    ? 'badge-critical'
    : findingsCount === 0
      ? 'badge-ok'
      : 'badge-medium';

  return (
    <div className="card min-w-0 flex flex-col gap-4 h-full">
      {/* Header: framework name + short description */}
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-title text-sentinel-text-primary">
              {frameworkLabel}
            </h3>
            <span className={clsx('badge', BADGE_CLASSES[badgeColor])}>
              {badgeColor}
            </span>
          </div>
          <p className="text-caption text-sentinel-text-secondary mt-2">
            {description}
          </p>
        </div>
      </div>

      {/* Body: ordered list of controls */}
      {references.length > 0 ? (
        <ol className="flex flex-col">
          {references.map((ref, idx) => {
            const isLast = idx === references.length - 1;
            const row = (
              <div
                className={clsx(
                  'flex items-start gap-3 py-3',
                  !isLast && 'border-b border-sentinel-border-soft',
                )}
              >
                <span className="font-mono text-caption text-sentinel-text-faint mt-px w-5 shrink-0 tabular-nums">
                  {String(idx + 1).padStart(2, '0')}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-caption font-semibold text-sentinel-text-primary truncate">
                    {ref.identifier}
                  </div>
                  <div className="text-caption text-sentinel-text-secondary mt-1">
                    {ref.title}
                  </div>
                </div>
                {ref.url && (
                  <ExternalLink
                    size={12}
                    className="mt-1 shrink-0 text-sentinel-text-tertiary group-hover:text-sentinel-text-primary transition-colors duration-150"
                    aria-hidden
                  />
                )}
              </div>
            );

            return (
              <li key={`${ref.identifier}-${idx}`}>
                {ref.url ? (
                  <button
                    type="button"
                    onClick={() => {
                      void openExternal(ref.url as string);
                    }}
                    className="w-full text-left cursor-pointer rounded-lg -mx-3 px-3 group transition-colors duration-150 hover:bg-sentinel-raised focus-visible:outline-none focus-visible:shadow-focus"
                    aria-label={`Open reference ${ref.identifier} in browser`}
                    title={ref.url}
                  >
                    {row}
                  </button>
                ) : (
                  row
                )}
              </li>
            );
          })}
        </ol>
      ) : (
        <div className="rounded-lg border border-dashed border-sentinel-border-soft px-4 py-4 text-center text-caption text-sentinel-text-tertiary">
          No controls mapped yet.
        </div>
      )}

      {/* Footer: findings counter badge */}
      <div className="mt-auto border-t border-sentinel-border-soft pt-4 flex items-center justify-between gap-3">
        <span className="section-heading">Coverage</span>
        <span className={clsx('badge tabular-nums', badgeClass)}>
          {findingsCount} {findingsCount === 1 ? 'finding mapped' : 'findings mapped'}
        </span>
      </div>
    </div>
  );
}

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

const BADGE_CLASSES: Record<ComplianceBadgeColor, string> = {
  purple:
    'text-[#e0c4ff] bg-[rgba(191,90,242,0.16)] border-[rgba(191,90,242,0.36)]',
  blue: 'text-[#bcdcff] bg-[rgba(10,132,255,0.16)] border-[rgba(10,132,255,0.30)]',
  green:
    'text-[#b8f5c8] bg-[rgba(52,199,89,0.16)] border-[rgba(52,199,89,0.30)]',
  orange:
    'text-[#ffd8a0] bg-[rgba(255,159,10,0.16)] border-[rgba(255,159,10,0.30)]',
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
  const pillClass = hasCritical
    ? 'pill-red'
    : findingsCount === 0
      ? 'pill-green'
      : 'pill-orange';

  return (
    <div className="card min-w-0 flex flex-col gap-4 h-full">
      {/* Header: framework name + short description */}
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-[15px] font-semibold text-sentinel-text-primary">
              {frameworkLabel}
            </h3>
            <span
              className={clsx(
                'rounded-pill px-2 py-0.5 text-[10px] font-semibold tracking-wide uppercase border',
                BADGE_CLASSES[badgeColor],
              )}
            >
              {badgeColor}
            </span>
          </div>
          <p className="text-[12px] text-sentinel-text-secondary mt-1 leading-snug">
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
                  'flex items-start gap-3 py-2.5',
                  !isLast && 'border-b border-white/[0.08]',
                )}
              >
                <span className="text-[10px] font-mono text-sentinel-text-tertiary mt-1 w-5 shrink-0 tabular-nums">
                  {String(idx + 1).padStart(2, '0')}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-[11px] font-semibold text-sentinel-text-primary truncate">
                    {ref.identifier}
                  </div>
                  <div className="text-[12px] text-sentinel-text-secondary mt-0.5 leading-snug">
                    {ref.title}
                  </div>
                </div>
                {ref.url && (
                  <ExternalLink
                    size={12}
                    className="mt-1 shrink-0 text-sentinel-text-tertiary group-hover:text-sentinel-text-primary transition-colors"
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
                    className="w-full text-left transition-colors cursor-pointer hover:bg-white/5 rounded-md -mx-2 px-2 group"
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
        <div className="text-[12px] text-sentinel-text-tertiary py-2">
          No controls mapped yet.
        </div>
      )}

      {/* Footer: findings counter pill */}
      <div className="mt-auto pt-1 flex items-center justify-between">
        <span className="section-heading">Coverage</span>
        <span className={clsx('pill', pillClass)}>
          {findingsCount} {findingsCount === 1 ? 'finding mapped' : 'findings mapped'}
        </span>
      </div>
    </div>
  );
}

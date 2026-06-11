// LookalikeDetailDialog — frosted-glass Radix Dialog that explains *why* a
// given registry candidate was flagged as a lookalike. Surfaces the four
// component sub-scores from L11's `score_breakdown` ({ name, description,
// tools, enums }) as horizontal bars so an operator can see at a glance
// whether the match is driven by brand-name confusion, marketing copy, or
// (more dangerous) tool-signature overlap.
// Implemented by Agent L15.

import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';

import type { LookalikeMatch } from '@/api/contract';

/**
 * L11 augments `LookalikeMatch` with a per-feature score breakdown. The field
 * may be absent in older payloads (Rust → JSON round-trip can omit it when
 * the engine bails out early), so we read it defensively from a structural
 * cast rather than tightening the shared contract here — that is L11's job.
 */
interface ScoreBreakdown {
  name?: number;
  description?: number;
  tools?: number;
  enums?: number;
}

function getBreakdown(row: LookalikeMatch): ScoreBreakdown {
  const sb = (row as unknown as { score_breakdown?: ScoreBreakdown })
    .score_breakdown;
  return sb ?? {};
}

function pct(v: number | undefined): string {
  if (v === undefined || Number.isNaN(v)) return '—';
  return `${(v * 100).toFixed(1)}%`;
}

function clampWidth(v: number | undefined): string {
  if (v === undefined || Number.isNaN(v)) return '0%';
  const clamped = Math.max(0, Math.min(1, v));
  return `${(clamped * 100).toFixed(2)}%`;
}

interface ScoreBarProps {
  label: string;
  value: number | undefined;
}

function ScoreBar({ label, value }: ScoreBarProps) {
  const has = value !== undefined && !Number.isNaN(value);
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between text-caption">
        <span className="text-sentinel-text-secondary">{label}</span>
        <span
          className={
            has
              ? 'font-mono tabular-nums text-sentinel-text-primary'
              : 'font-mono tabular-nums text-sentinel-text-tertiary'
          }
        >
          {pct(value)}
        </span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-white/6 overflow-hidden">
        <div
          className="h-full rounded-full bg-sentinel-accent"
          style={{ width: clampWidth(value) }}
          aria-hidden
        />
      </div>
    </div>
  );
}

export interface LookalikeDetailDialogProps {
  row: LookalikeMatch | null;
  onOpenChange: (open: boolean) => void;
}

export default function LookalikeDetailDialog({
  row,
  onOpenChange,
}: LookalikeDetailDialogProps) {
  const open = row !== null;
  const breakdown = row ? getBreakdown(row) : {};

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-xs data-[state=open]:animate-fade-up"
        />
        <Dialog.Content
          className="surface-raised shadow-overlay fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl p-6 data-[state=open]:animate-fade-up"
        >
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-title text-sentinel-text-primary">
                Match details
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-body text-sentinel-text-secondary">
                Per-feature similarity scores that produced this lookalike
                flag.
              </Dialog.Description>
            </div>
            <Dialog.Close
              className="shrink-0 rounded-lg border border-sentinel-border bg-sentinel-inset p-2 text-sentinel-text-secondary transition-colors duration-150 hover:bg-sentinel-raised hover:border-sentinel-border-strong hover:text-sentinel-text-primary focus-visible:outline-none focus-visible:shadow-focus"
              aria-label="Close match details"
            >
              <X className="h-4 w-4" aria-hidden />
            </Dialog.Close>
          </div>

          {row && (
            <div className="mt-6 flex flex-col gap-4">
              {/* Identity block */}
              <dl className="grid grid-cols-[110px_1fr] gap-x-4 gap-y-2 text-caption">
                <dt className="section-heading">Declared</dt>
                <dd
                  className="font-mono text-caption text-sentinel-text-primary break-all"
                  title={row.declared_package}
                >
                  {row.declared_package}
                </dd>
                <dt className="section-heading">Candidate</dt>
                <dd
                  className="font-mono text-caption text-sentinel-text-primary break-all"
                  title={row.candidate_name}
                >
                  <span className="text-sentinel-text-tertiary">
                    {row.registry} /
                  </span>{' '}
                  {row.candidate_name}
                </dd>
                <dt className="section-heading">Score</dt>
                <dd className="font-mono tabular-nums text-caption text-sentinel-text-primary">
                  {pct(row.similarity_score)}
                </dd>
              </dl>

              {/* Breakdown bars */}
              <div className="rounded-lg border border-sentinel-border bg-sentinel-inset p-4 flex flex-col gap-3">
                <div className="section-heading">Score breakdown</div>
                <ScoreBar label="Name" value={breakdown.name} />
                <ScoreBar label="Description" value={breakdown.description} />
                <ScoreBar label="Tools" value={breakdown.tools} />
                <ScoreBar label="Enums" value={breakdown.enums} />
              </div>

              {/* Weighting footnote */}
              <p className="text-caption leading-relaxed text-sentinel-text-tertiary">
                Weights: name 30%, description 25%, tools 30%, enums 15%
                (renormalized when tool signatures are unavailable).
              </p>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

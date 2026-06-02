// InvestigateDialog — frosted-glass Radix Dialog used to open an investigation
// on a server. Captures a free-form note and the operator who flagged it, then
// dispatches `api.createInvestigation` (added by V6) and chains an
// `apply_approval` with the `investigate` decision so the server's status
// updates in the same gesture.
// Implemented by Agent V7.

import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { Loader2, Search } from 'lucide-react';

import { api } from '../api/tauri';
import type { Investigation } from '../api/contract';

// In-process pub/sub so the ServerDetailDrawer's "Investigations" section can
// re-render the moment a new note is recorded, without having to poll. The
// Rust backend persists the row regardless; this is purely a UI heads-up.
const listeners = new Set<() => void>();

function notifyInvestigationListeners() {
  for (const fn of listeners) fn();
}

export function subscribeInvestigations(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export interface InvestigateDialogProps {
  serverId: string | null;
  endpoint?: string | null;
  defaultOperator?: string;
  onOpenChange: (open: boolean) => void;
  /**
   * Called once the investigation has been recorded AND the matching
   * `apply_approval` (decision: 'investigate') has succeeded. Pages use it
   * to revalidate their SWR caches.
   */
  onSubmitted?: (entry: Investigation) => void | Promise<void>;
}

const MIN_NOTE_LENGTH = 10;

export default function InvestigateDialog({
  serverId,
  endpoint,
  defaultOperator = 'operator@local',
  onOpenChange,
  onSubmitted,
}: InvestigateDialogProps) {
  const open = serverId !== null;

  const [note, setNote] = useState('');
  const [operator, setOperator] = useState(defaultOperator);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset form whenever the target server changes (including on close).
  useEffect(() => {
    if (!open) {
      // Defer the reset so the closing animation isn't visually disrupted.
      const t = setTimeout(() => {
        setNote('');
        setOperator(defaultOperator);
        setError(null);
        setSubmitting(false);
      }, 200);
      return () => clearTimeout(t);
    }
    setNote('');
    setOperator(defaultOperator);
    setError(null);
    setSubmitting(false);
    return undefined;
  }, [open, serverId, defaultOperator]);

  const trimmedNote = note.trim();
  const noteValid = trimmedNote.length >= MIN_NOTE_LENGTH;
  const operatorTrimmed = operator.trim();
  const canSubmit = noteValid && operatorTrimmed.length > 0 && !submitting;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!serverId || !canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const entry = await api.createInvestigation(
        serverId,
        trimmedNote,
        operatorTrimmed,
      );
      // Let any open drawer's "Investigations" list refresh immediately.
      notifyInvestigationListeners();
      await api.applyApproval(serverId, {
        decision: 'investigate',
        operator: operatorTrimmed,
      });
      if (onSubmitted) await onSubmitted(entry);
      onOpenChange(false);
    } catch (err) {
      console.error('[InvestigateDialog] failed to open investigation', err);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog.Root
      open={open}
      onOpenChange={(next) => {
        if (submitting) return;
        onOpenChange(next);
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm data-[state=open]:animate-fade-up"
        />
        <Dialog.Content
          className="glass-strong fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-glass p-6 data-[state=open]:animate-fade-up"
          onOpenAutoFocus={(evt) => {
            // Keep focus on the textarea rather than the close button.
            evt.preventDefault();
            const el = document.getElementById(
              'investigate-dialog-note',
            ) as HTMLTextAreaElement | null;
            el?.focus();
          }}
        >
          <div className="flex items-start gap-3">
            <span
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-white/[0.08] text-sentinel-text-primary"
              aria-hidden
            >
              <Search size={16} />
            </span>
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-[17px] font-semibold text-sentinel-text-primary">
                Open an investigation
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sentinel-text-secondary">
                Capture why this server needs a closer look. The note will be
                attached to the signed audit bundle.
              </Dialog.Description>
            </div>
          </div>

          {endpoint && (
            <div className="mt-4 truncate rounded-pill px-3 py-1.5 font-mono text-[12px] text-sentinel-text-secondary bg-white/5 border border-white/10">
              {endpoint}
            </div>
          )}

          <form className="mt-5 flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1.5">
              <label
                htmlFor="investigate-dialog-note"
                className="text-[12px] font-medium text-sentinel-text-secondary"
              >
                Note <span className="text-sentinel-text-tertiary">(required)</span>
              </label>
              <textarea
                id="investigate-dialog-note"
                className="min-h-[96px] resize-y rounded-glass border border-white/10 bg-black/30 px-3 py-2 text-[13px] text-sentinel-text-primary placeholder:text-sentinel-text-tertiary focus:border-sentinel-blue-glow/70 focus:outline-none focus:ring-1 focus:ring-sentinel-blue-glow/60"
                placeholder="What looked off? Link any captured traces."
                value={note}
                onChange={(e) => setNote(e.target.value)}
                minLength={MIN_NOTE_LENGTH}
                required
                disabled={submitting}
              />
              <div className="flex items-center justify-between text-[11px] text-sentinel-text-tertiary">
                <span>
                  {noteValid
                    ? 'Looks good.'
                    : `At least ${MIN_NOTE_LENGTH} characters.`}
                </span>
                <span>{trimmedNote.length} chars</span>
              </div>
            </div>

            <div className="flex flex-col gap-1.5">
              <label
                htmlFor="investigate-dialog-operator"
                className="text-[12px] font-medium text-sentinel-text-secondary"
              >
                Tagged by
              </label>
              <input
                id="investigate-dialog-operator"
                type="text"
                className="rounded-glass border border-white/10 bg-black/30 px-3 py-2 text-[13px] text-sentinel-text-primary placeholder:text-sentinel-text-tertiary focus:border-sentinel-blue-glow/70 focus:outline-none focus:ring-1 focus:ring-sentinel-blue-glow/60"
                value={operator}
                onChange={(e) => setOperator(e.target.value)}
                placeholder="operator@local"
                required
                disabled={submitting}
              />
            </div>

            {error && (
              <div
                role="alert"
                className="rounded-glass border border-sentinel-red/60 bg-sentinel-red/10 px-3 py-2 text-[12px] text-sentinel-red"
              >
                {error}
              </div>
            )}

            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close asChild>
                <button
                  type="button"
                  className="btn"
                  disabled={submitting}
                >
                  Cancel
                </button>
              </Dialog.Close>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={!canSubmit}
              >
                {submitting ? (
                  <Loader2 size={14} className="animate-spin" aria-hidden />
                ) : (
                  <Search size={14} aria-hidden />
                )}
                Open investigation
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

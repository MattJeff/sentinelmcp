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
import { useToastStore } from '../hooks/useToast';

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
  const pushToast = useToastStore((s) => s.push);

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
      pushToast({
        title: 'Investigation opened',
        description:
          'Server tagged "to investigate". The note is saved and will appear in the server drawer and the signed audit bundle.',
        severity: 'info',
      });
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
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-xs data-[state=open]:animate-fade-up"
        />
        <Dialog.Content
          className="surface-raised fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-xl p-6 shadow-overlay data-[state=open]:animate-fade-up"
          onOpenAutoFocus={(evt) => {
            // Keep focus on the textarea rather than the close button.
            evt.preventDefault();
            const el = document.getElementById(
              'investigate-dialog-note',
            ) as HTMLTextAreaElement | null;
            el?.focus();
          }}
        >
          <div className="flex items-start gap-4">
            <span
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-sentinel-accent-dim text-sentinel-accent"
              aria-hidden
            >
              <Search size={16} />
            </span>
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-title text-sentinel-text-primary">
                Open an investigation
              </Dialog.Title>
              <Dialog.Description className="mt-2 text-body text-sentinel-text-secondary">
                Tags the server <strong>to investigate</strong> (moves it out of
                the Approvals queue), saves your note in the audit log, and
                attaches it to the signed compliance bundle. You can still
                Approve or Block it later from the server drawer.
              </Dialog.Description>
            </div>
          </div>

          {endpoint && (
            <div className="mt-4 truncate rounded-lg px-3 py-2 font-mono text-caption text-sentinel-text-tertiary bg-sentinel-inset border border-sentinel-border">
              {endpoint}
            </div>
          )}

          <form className="mt-6 flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-2">
              <label
                htmlFor="investigate-dialog-note"
                className="text-caption font-medium text-sentinel-text-secondary"
              >
                Note <span className="text-sentinel-text-tertiary">(required)</span>
              </label>
              <textarea
                id="investigate-dialog-note"
                className="input h-auto min-h-[96px] resize-y py-2"
                placeholder="What looked off? Link any captured traces."
                value={note}
                onChange={(e) => setNote(e.target.value)}
                minLength={MIN_NOTE_LENGTH}
                required
                disabled={submitting}
              />
              <div className="flex items-center justify-between text-caption text-sentinel-text-tertiary">
                <span>
                  {noteValid
                    ? 'Looks good.'
                    : `At least ${MIN_NOTE_LENGTH} characters.`}
                </span>
                <span className="tabular-nums">{trimmedNote.length} chars</span>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <label
                htmlFor="investigate-dialog-operator"
                className="text-caption font-medium text-sentinel-text-secondary"
              >
                Tagged by
              </label>
              <input
                id="investigate-dialog-operator"
                type="text"
                className="input"
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
                className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-3 py-2 text-caption text-sentinel-critical"
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

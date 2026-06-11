// EnforcementConfirmDialog — second-confirmation dialog shown when the
// optional enforcement mode (Settings → Enforcement) is enabled and the
// operator clicks "Block" on a server. Surfaces the exact config file
// that will be rewritten and the path of the backup that will be
// written next to it, so the action is auditable before it lands on disk.
//
// Two buttons:
//   • "Cancel"            — closes the dialog, no side-effect.
//   • "Remove from config" — calls the parent's `onConfirm`, which in
//                            turn invokes `api.enforcementRemoveServer`.
//
// This component is presentation-only: the network call, toast, restore
// link and the follow-up `applyApproval('block')` are owned by the
// caller (ApprovalsPage / ServerDetailDrawer) so the dialog stays
// trivially reusable.

import { useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { AlertTriangle, FileWarning, Loader2 } from 'lucide-react';
import clsx from 'clsx';

export interface EnforcementConfirmDialogProps {
  /** Truthy value opens the dialog; `null` closes it. */
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Server endpoint (e.g. `filesystem-server (stdio)`) for context. */
  endpoint: string | null;
  /**
   * Absolute path of the AI-client config file Sentinel will rewrite.
   * Pass `null` if unknown — the dialog renders a `(detected on confirm)`
   * placeholder so the operator still understands what is about to happen.
   */
  configPath: string | null;
  /**
   * Absolute path of the backup file that will be written. Same
   * placeholder semantics as `configPath`.
   */
  backupPath: string | null;
  /**
   * Triggered when the operator confirms. The caller awaits the real
   * `enforcementRemoveServer` call; while the promise is pending the
   * dialog shows a spinner and disables both buttons.
   */
  onConfirm: () => Promise<void> | void;
}

export default function EnforcementConfirmDialog({
  open,
  onOpenChange,
  endpoint,
  configPath,
  backupPath,
  onConfirm,
}: EnforcementConfirmDialogProps) {
  const [busy, setBusy] = useState(false);

  const handleConfirm = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root
      open={open}
      onOpenChange={(next) => {
        if (busy) return; // can't escape while the rewrite is in flight
        onOpenChange(next);
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/50 backdrop-blur-xs data-[state=open]:animate-fade-up" />
        <Dialog.Content
          className="surface-raised fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-xl p-6 shadow-overlay data-[state=open]:animate-fade-up"
        >
          <div className="flex items-start gap-4">
            <span
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-sentinel-critical-bg text-sentinel-critical"
              aria-hidden
            >
              <FileWarning size={16} />
            </span>
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-title text-sentinel-text-primary">
                Remove this server from your AI-client config?
              </Dialog.Title>
              <Dialog.Description className="mt-2 text-body text-sentinel-text-secondary">
                Enforcement mode is enabled. Sentinel will rewrite the
                declaring config file on disk and drop a timestamped backup
                next to it. The agent that owns the file will see the change
                on its next read.
              </Dialog.Description>
            </div>
          </div>

          {endpoint && (
            <div className="mt-4 truncate rounded-lg px-3 py-2 font-mono text-caption text-sentinel-text-tertiary bg-sentinel-inset border border-sentinel-border">
              {endpoint}
            </div>
          )}

          <dl className="mt-6 flex flex-col gap-4 text-caption">
            <PathRow label="Config to rewrite" value={configPath} />
            <PathRow label="Backup written to" value={backupPath} />
          </dl>

          <div
            className="mt-6 flex items-start gap-3 rounded-lg border border-sentinel-medium-border bg-sentinel-medium-bg px-3 py-2 text-caption text-sentinel-text-secondary"
            role="note"
          >
            <AlertTriangle size={13} className="mt-px shrink-0 text-sentinel-medium" aria-hidden />
            <span>
              Restore is a single click — Sentinel can put the backup back
              over the config if the agent needs the server again.
            </span>
          </div>

          <div className="mt-8 flex justify-end gap-2">
            <Dialog.Close asChild>
              <button type="button" className="btn" disabled={busy}>
                Cancel
              </button>
            </Dialog.Close>
            <button
              type="button"
              className={clsx('btn btn-danger inline-flex items-center gap-2')}
              onClick={handleConfirm}
              disabled={busy}
            >
              {busy && <Loader2 size={14} className="animate-spin" aria-hidden />}
              {busy ? 'Removing…' : 'Remove from config'}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function PathRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <dt className="section-heading mb-1">
        {label}
      </dt>
      <dd
        className={clsx(
          'font-mono break-all rounded-lg border px-3 py-2 text-caption',
          value
            ? 'bg-sentinel-inset border-sentinel-border text-sentinel-text-primary'
            : 'bg-sentinel-inset border-dashed border-sentinel-border text-sentinel-text-faint',
        )}
      >
        {value ?? '(detected on confirm)'}
      </dd>
    </div>
  );
}

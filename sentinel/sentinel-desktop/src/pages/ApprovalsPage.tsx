// Approval workflow page — operators sweep through every unapproved MCP
// server and choose Approve / Investigate / Block. Each decision feeds
// the signed audit bundle. Implemented by Agent UI-5.

import { useState } from 'react';
import useSWR, { mutate } from 'swr';
import * as Dialog from '@radix-ui/react-dialog';
import * as Tooltip from '@radix-ui/react-tooltip';
import clsx from 'clsx';
import { api } from '../api/tauri';
import {
  COMMANDS,
  type ApprovalDecision,
  type ServerCard,
} from '../api/contract';

const OPERATOR = 'operator@local';

export default function ApprovalsPage() {
  const { data, isLoading, mutate: mutateLocal } = useSWR<ServerCard[]>(
    COMMANDS.listServers,
    () => api.listServers(),
  );

  // Optimistic removal: ids that have just been decided.
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());
  // Ids whose decision failed — render an inline "Failed — try again" pill.
  const [failedIds, setFailedIds] = useState<Set<string>>(new Set());
  const [blockTarget, setBlockTarget] = useState<ServerCard | null>(null);
  // Approved-since-mount counter, surfaced as a top inline status.
  const [approvedCount, setApprovedCount] = useState(0);

  const queue = (data ?? [])
    .filter((s) => s.status !== 'approved')
    .filter((s) => !pendingIds.has(s.id));

  async function decide(
    server: ServerCard,
    decision: ApprovalDecision['decision'],
  ) {
    // Clear any prior failure pill on retry.
    setFailedIds((prev) => {
      if (!prev.has(server.id)) return prev;
      const next = new Set(prev);
      next.delete(server.id);
      return next;
    });
    setPendingIds((prev) => {
      const next = new Set(prev);
      next.add(server.id);
      return next;
    });
    try {
      await api.applyApproval(server.id, { decision, operator: OPERATOR });
      // Revalidate this page's SWR cache and broadcast the same cache key
      // globally so InventoryPage sees the new status on its next mount.
      await mutateLocal();
      await mutate(COMMANDS.listServers);
      if (decision === 'approve') {
        setApprovedCount((n) => n + 1);
      }
    } catch (err) {
      console.error('[Approvals] applyApproval failed', err);
      // Roll back optimistic removal on failure and surface a pill.
      setPendingIds((prev) => {
        const next = new Set(prev);
        next.delete(server.id);
        return next;
      });
      setFailedIds((prev) => {
        const next = new Set(prev);
        next.add(server.id);
        return next;
      });
    }
  }

  return (
    <Tooltip.Provider delayDuration={200}>
      <div className="flex flex-col gap-6 animate-fade-up mx-auto w-full max-w-[1400px]">
      <header className="flex flex-col gap-2">
        <h1 className="text-[28px] font-semibold tracking-tight text-sentinel-text-primary">
          Approvals
        </h1>
        <p className="max-w-2xl text-[13px] text-sentinel-text-secondary">
          Review every server your agents reach. Each decision becomes part
          of the signed bundle.
        </p>
      </header>

      {approvedCount > 0 && (
        <div
          role="status"
          aria-live="polite"
          className="sticky top-0 z-10 self-start pill pill-green animate-fade-up backdrop-blur-md"
        >
          Approved {approvedCount}{' '}
          {approvedCount === 1 ? 'server' : 'servers'} since opening this page
        </div>
      )}

      {isLoading ? (
        <div className="flex flex-col gap-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="skeleton h-[88px] w-full" />
          ))}
        </div>
      ) : queue.length === 0 ? (
        <EmptyState />
      ) : (
        <ul className="flex flex-col gap-3">
          {queue.map((server) => (
            <li key={server.id} className="animate-fade-up">
              <ApprovalRow
                server={server}
                failed={failedIds.has(server.id)}
                onApprove={() => decide(server, 'approve')}
                onInvestigate={() => decide(server, 'investigate')}
                onBlock={() => setBlockTarget(server)}
              />
            </li>
          ))}
        </ul>
      )}

      <BlockConfirmDialog
        server={blockTarget}
        onOpenChange={(open) => {
          if (!open) setBlockTarget(null);
        }}
        onConfirm={async () => {
          if (!blockTarget) return;
          const target = blockTarget;
          setBlockTarget(null);
          await decide(target, 'block');
        }}
      />
      </div>
    </Tooltip.Provider>
  );
}

// ── Row ────────────────────────────────────────────────────────────────

interface ApprovalRowProps {
  server: ServerCard;
  failed: boolean;
  onApprove: () => void;
  onInvestigate: () => void;
  onBlock: () => void;
}

function ApprovalRow({
  server,
  failed,
  onApprove,
  onInvestigate,
  onBlock,
}: ApprovalRowProps) {
  const dotClass =
    server.color === 'green'
      ? 'dot-green'
      : server.color === 'orange'
        ? 'dot-orange'
        : 'dot-red';

  const transportPill =
    server.transport === 'http' ? 'pill-blue' : 'pill-green';

  const scopesLabel =
    server.scopes.length > 0 ? server.scopes.join(', ') : 'none';

  return (
    <div
      className={clsx(
        'card-hover flex flex-col gap-4 lg:flex-row lg:items-center lg:gap-6',
        server.color === 'red' && 'shadow-glow-red',
      )}
    >
      {/* Left: dot + endpoint + transport */}
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <span className={clsx('dot shrink-0', dotClass)} aria-hidden />
        <Tooltip.Root>
          <Tooltip.Trigger asChild>
            <span className="truncate font-mono text-[13px] font-semibold text-sentinel-text-primary min-w-0">
              {server.endpoint}
            </span>
          </Tooltip.Trigger>
          <Tooltip.Portal>
            <Tooltip.Content
              side="top"
              sideOffset={6}
              className="z-50 max-w-[90vw] break-all rounded-md bg-black/80 px-2 py-1 font-mono text-[11px] text-white shadow-glass-soft border border-white/10"
            >
              {server.endpoint}
              <Tooltip.Arrow className="fill-black/80" />
            </Tooltip.Content>
          </Tooltip.Portal>
        </Tooltip.Root>
        <span className={clsx('pill shrink-0', transportPill)}>
          {server.transport}
        </span>
        {failed && (
          <span
            className="pill pill-red shrink-0 animate-fade-up"
            role="alert"
          >
            Failed — try again
          </span>
        )}
      </div>

      {/* Center: short summary */}
      <div className="min-w-0 flex-1 text-[12px] text-sentinel-text-secondary">
        {server.tool_count} {server.tool_count === 1 ? 'tool' : 'tools'} ·
        scopes: {scopesLabel}
      </div>

      {/* Right: actions — wrap below the description on narrow viewports */}
      <div className="flex flex-wrap items-center gap-2 lg:shrink-0 lg:flex-nowrap">
        <button
          type="button"
          className="btn btn-primary"
          onClick={onApprove}
        >
          Approve
        </button>
        <button type="button" className="btn" onClick={onInvestigate}>
          Investigate
        </button>
        <button type="button" className="btn btn-danger" onClick={onBlock}>
          Block
        </button>
      </div>
    </div>
  );
}

// ── Empty state ────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="card flex flex-col items-center justify-center gap-2 py-16 text-center animate-fade-up">
      <div className="text-[15px] font-semibold text-sentinel-text-primary">
        All servers reviewed. Audit-ready.
      </div>
      <p className="max-w-md text-[12px] text-sentinel-text-tertiary">
        New discoveries will appear here automatically.
      </p>
    </div>
  );
}

// ── Block confirmation dialog ──────────────────────────────────────────

interface BlockConfirmDialogProps {
  server: ServerCard | null;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
}

function BlockConfirmDialog({
  server,
  onOpenChange,
  onConfirm,
}: BlockConfirmDialogProps) {
  return (
    <Dialog.Root open={server !== null} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm data-[state=open]:animate-fade-up"
        />
        <Dialog.Content
          className="glass-strong fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-glass p-6 data-[state=open]:animate-fade-up"
        >
          <Dialog.Title className="text-[17px] font-semibold text-sentinel-text-primary">
            Block this server?
          </Dialog.Title>
          <Dialog.Description className="mt-2 text-[13px] text-sentinel-text-secondary">
            Agents won't be able to reach this endpoint. Stored as a finding.
          </Dialog.Description>
          {server && (
            <div className="mt-4 truncate rounded-pill px-3 py-1.5 font-mono text-[12px] text-sentinel-text-secondary bg-white/5 border border-white/10">
              {server.endpoint}
            </div>
          )}
          <div className="mt-6 flex justify-end gap-2">
            <Dialog.Close asChild>
              <button type="button" className="btn">
                Cancel
              </button>
            </Dialog.Close>
            <button
              type="button"
              className="btn btn-danger"
              onClick={onConfirm}
            >
              Block
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

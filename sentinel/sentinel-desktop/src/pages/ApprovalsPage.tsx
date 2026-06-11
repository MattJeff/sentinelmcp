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
  type DiscoveredClient,
  type DiscoveredClientKind,
  type DiscoveryReport,
  type EnforcementRemoveResult,
  type ServerCard,
  type Settings,
} from '../api/contract';
import InvestigateDialog from '../components/InvestigateDialog';
import EnforcementConfirmDialog from '../components/EnforcementConfirmDialog';
import { useToastStore } from '../hooks/useToast';

const OPERATOR = 'operator@local';

// Best-effort: strip the trailing transport hint from a server endpoint to
// match the `name` field used by AI-client config files (e.g.
// `filesystem-server (stdio)` → `filesystem-server`).
function deriveDeclaredName(endpoint: string): string {
  const match = endpoint.match(/^(.*?)\s*\((?:stdio|http)\)\s*$/i);
  return match ? match[1].trim() : endpoint;
}

interface DeclaringClient {
  kind: DiscoveredClientKind;
  configPath: string | null;
}

/**
 * Walk the Discovery snapshot to find which AI client declares `endpoint`.
 * Returns `null` when the snapshot is empty or the server isn't matched —
 * the backend will still resolve at confirm time, and the dialog gracefully
 * renders a `(detected on confirm)` placeholder.
 */
function findDeclaringClient(
  report: DiscoveryReport | undefined,
  endpoint: string,
): DeclaringClient | null {
  if (!report) return null;
  const needle = deriveDeclaredName(endpoint).toLowerCase();
  for (const client of report.clients as DiscoveredClient[]) {
    if (!client.installed) continue;
    const match = client.servers.find(
      (s) => s.name.toLowerCase() === needle,
    );
    if (match) {
      return {
        kind: client.kind,
        configPath: client.configs[0] ?? null,
      };
    }
  }
  return null;
}

export default function ApprovalsPage() {
  const { data, isLoading, mutate: mutateLocal } = useSWR<ServerCard[]>(
    COMMANDS.listServers,
    () => api.listServers(),
  );

  // Surface the enforcement toggle and the latest Discovery snapshot so the
  // Block flow knows (a) whether to escalate to the enforcement dialog and
  // (b) which client config will be rewritten.
  const { data: settings } = useSWR<Settings>(
    COMMANDS.getSettings,
    () => api.getSettings(),
  );
  const { data: discovery } = useSWR<DiscoveryReport>(
    COMMANDS.discoverSystem,
    () => api.discoverSystem(),
  );
  const enforcementEnabled = settings?.enforcement?.enabled ?? false;

  // Optimistic removal: ids that have just been decided.
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());
  // Ids whose decision failed — render an inline "Failed — try again" pill.
  const [failedIds, setFailedIds] = useState<Set<string>>(new Set());
  const [blockTarget, setBlockTarget] = useState<ServerCard | null>(null);
  const [enforceTarget, setEnforceTarget] = useState<ServerCard | null>(null);
  const [investigateTarget, setInvestigateTarget] =
    useState<ServerCard | null>(null);
  // Approved-since-mount counter, surfaced as a top inline status.
  const [approvedCount, setApprovedCount] = useState(0);

  const pushToast = useToastStore((s) => s.push);

  // Backup of the last enforcement removal, so we can offer a one-click
  // "Restore from backup" link to the operator.
  const [lastBackup, setLastBackup] = useState<EnforcementRemoveResult | null>(
    null,
  );
  const [restoring, setRestoring] = useState(false);

  // Resolve the AI client that declares the target server, used to populate
  // the enforcement dialog's paths and the `clientKind` arg.
  const declaringClient = enforceTarget
    ? findDeclaringClient(discovery, enforceTarget.endpoint)
    : null;

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
      <div className="flex flex-col gap-8 animate-fade-up mx-auto w-full max-w-[1400px]">
      <header className="flex flex-col gap-2">
        <h1 className="text-metric-lg text-sentinel-text-primary">
          Approvals
        </h1>
        <p className="max-w-2xl text-body text-sentinel-text-secondary">
          Review every server your agents reach. Each decision becomes part
          of the signed bundle.
        </p>
      </header>

      {approvedCount > 0 && (
        <div
          role="status"
          aria-live="polite"
          className="sticky top-0 z-10 self-start badge badge-ok tabular-nums animate-fade-up"
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
                onInvestigate={() => setInvestigateTarget(server)}
                onBlock={() =>
                  // When enforcement is enabled, the Block button opens the
                  // EnforcementConfirmDialog (config rewrite + backup). When
                  // disabled, fall back to the original advisory confirmation.
                  enforcementEnabled
                    ? setEnforceTarget(server)
                    : setBlockTarget(server)
                }
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

      <EnforcementConfirmDialog
        open={enforceTarget !== null}
        onOpenChange={(open) => {
          if (!open) setEnforceTarget(null);
        }}
        endpoint={enforceTarget?.endpoint ?? null}
        configPath={declaringClient?.configPath ?? null}
        backupPath={
          declaringClient?.configPath
            ? `${declaringClient.configPath}.sentinel-backup`
            : null
        }
        onConfirm={async () => {
          if (!enforceTarget) return;
          const target = enforceTarget;
          try {
            const result = await api.enforcementRemoveServer(
              target.id,
              declaringClient?.kind ?? null,
            );
            setEnforceTarget(null);
            if (result.ok) {
              setLastBackup(result);
              pushToast({
                title: 'Removed from AI client config',
                description: `Config: ${result.config_path} · Backup: ${result.backup_path}`,
                severity: 'info',
              });
              // Mirror the advisory side-effect: the server is also marked
              // Bloque in Sentinel's own audit trail.
              await decide(target, 'block');
            } else {
              pushToast({
                title: 'Enforcement failed',
                description: result.error ?? 'Unknown error',
                severity: 'high',
              });
            }
          } catch (err) {
            setEnforceTarget(null);
            pushToast({
              title: 'Enforcement failed',
              description: err instanceof Error ? err.message : String(err),
              severity: 'high',
            });
          }
        }}
      />

      {lastBackup && (
        <div
          role="status"
          aria-live="polite"
          className="self-start surface rounded-lg px-3 py-2 text-caption text-sentinel-text-secondary inline-flex items-center gap-2 animate-fade-up"
        >
          <span className="font-mono text-caption text-sentinel-text-tertiary truncate max-w-xs">
            Backup: {lastBackup.backup_path}
          </span>
          <button
            type="button"
            className="text-sentinel-accent hover:underline disabled:opacity-40 focus-visible:outline-none focus-visible:shadow-focus rounded-lg transition-colors duration-150"
            disabled={restoring}
            onClick={async () => {
              if (!lastBackup || restoring) return;
              setRestoring(true);
              try {
                const r = await api.enforcementRestore(lastBackup.backup_path);
                if (r.ok) {
                  pushToast({
                    title: 'Restored from backup',
                    description: r.config_path,
                    severity: 'info',
                  });
                  setLastBackup(null);
                  await mutateLocal();
                  await mutate(COMMANDS.listServers);
                } else {
                  pushToast({
                    title: 'Restore failed',
                    description: r.error ?? 'Unknown error',
                    severity: 'high',
                  });
                }
              } catch (err) {
                pushToast({
                  title: 'Restore failed',
                  description: err instanceof Error ? err.message : String(err),
                  severity: 'high',
                });
              } finally {
                setRestoring(false);
              }
            }}
          >
            {restoring ? 'Restoring…' : 'Restore from backup'}
          </button>
        </div>
      )}

      <InvestigateDialog
        serverId={investigateTarget?.id ?? null}
        endpoint={investigateTarget?.endpoint ?? null}
        defaultOperator={OPERATOR}
        onOpenChange={(open) => {
          if (!open) setInvestigateTarget(null);
        }}
        onSubmitted={async () => {
          // The dialog already issued apply_approval(investigate) — reuse the
          // same optimistic-removal path so the row leaves the queue.
          const target = investigateTarget;
          setInvestigateTarget(null);
          if (target) {
            setPendingIds((prev) => {
              const next = new Set(prev);
              next.add(target.id);
              return next;
            });
          }
          await mutateLocal();
          await mutate(COMMANDS.listServers);
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
      ? 'dot-ok'
      : server.color === 'orange'
        ? 'dot-high'
        : 'dot-critical';

  const scopesLabel =
    server.scopes.length > 0 ? server.scopes.join(', ') : 'none';

  return (
    <div
      className={clsx(
        'card-hover flex flex-col gap-4 lg:flex-row lg:items-center lg:gap-6',
        server.color === 'red' && 'border-l-2 border-l-sentinel-critical-border',
      )}
    >
      {/* Left: dot + endpoint + transport */}
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <span className={clsx('dot shrink-0', dotClass)} aria-hidden />
        <Tooltip.Root>
          <Tooltip.Trigger asChild>
            <span className="truncate font-mono text-body font-medium text-sentinel-text-primary min-w-0">
              {server.endpoint}
            </span>
          </Tooltip.Trigger>
          <Tooltip.Portal>
            <Tooltip.Content
              side="top"
              sideOffset={6}
              className="z-50 max-w-[90vw] break-all rounded-lg bg-sentinel-raised px-2 py-1 font-mono text-overline text-sentinel-text-primary shadow-raised border border-sentinel-border-strong"
            >
              {server.endpoint}
              <Tooltip.Arrow className="fill-sentinel-raised" />
            </Tooltip.Content>
          </Tooltip.Portal>
        </Tooltip.Root>
        <span className="badge badge-neutral shrink-0">
          {server.transport}
        </span>
        {failed && (
          <span
            className="badge badge-critical shrink-0 animate-fade-up"
            role="alert"
          >
            Failed — try again
          </span>
        )}
      </div>

      {/* Center: short summary */}
      <div className="min-w-0 flex-1 text-caption text-sentinel-text-tertiary tabular-nums">
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
    <div className="card flex flex-col items-center justify-center gap-2 py-8 text-center animate-fade-up">
      <span className="dot dot-ok mb-2" aria-hidden />
      <div className="text-title text-sentinel-text-primary">
        All servers reviewed. Audit-ready.
      </div>
      <p className="max-w-md text-caption text-sentinel-text-tertiary">
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
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-xs data-[state=open]:animate-fade-up"
        />
        <Dialog.Content
          className="surface-raised fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-xl p-6 shadow-overlay data-[state=open]:animate-fade-up"
        >
          <Dialog.Title className="text-title text-sentinel-text-primary">
            Block this server?
          </Dialog.Title>
          <Dialog.Description className="mt-2 text-body text-sentinel-text-secondary">
            Agents won't be able to reach this endpoint. Stored as a finding.
          </Dialog.Description>
          {server && (
            <div className="mt-4 truncate rounded-lg px-3 py-2 font-mono text-caption text-sentinel-text-tertiary bg-sentinel-inset border border-sentinel-border">
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

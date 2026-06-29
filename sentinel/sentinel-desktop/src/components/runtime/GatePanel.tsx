// GatePanel — "Approve before run" (Vague D).
//
// Surfaces the approve-before-run gate policy and the queue of calls held for
// operator approval. The gate is opt-in: detection-only by default so the
// proxy keeps relaying bit-exact until the operator accepts the tradeoff of
// blocking risky calls (and the latency / friction that implies).

import { useState } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import {
  Check,
  Loader2,
  Lock,
  ShieldCheck,
  X,
} from 'lucide-react';

import { api } from '@/api/tauri';
import { COMMANDS, type GateConfig, type PendingApproval } from '@/api/contract';
import { useToast } from '@/hooks/useToast';
import SeverityBadge, { severityRank } from './SeverityBadge';

const SEUILS: { value: 'low' | 'medium' | 'high'; label: string; hint: string }[] = [
  { value: 'low', label: 'Low', hint: 'Hold anything above informational.' },
  { value: 'medium', label: 'Medium', hint: 'Hold medium-risk calls and up.' },
  { value: 'high', label: 'High', hint: 'Hold only high-risk calls (loosest).' },
];

/** Format an ISO timestamp as a short local time; falls back to the raw value. */
function formatRequestedAt(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/** Short, mono-friendly identity for a server UUID (first segment). */
function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

export default function GatePanel() {
  const { toast } = useToast();

  const {
    data: config,
    isLoading: configLoading,
    error: configError,
    mutate: mutateConfig,
  } = useSWR<GateConfig>(COMMANDS.getGateConfig, api.getGateConfig, {
    revalidateOnFocus: false,
  });

  const {
    data: pending,
    isLoading: pendingLoading,
    error: pendingError,
    mutate: mutatePending,
  } = useSWR<PendingApproval[]>(
    COMMANDS.listPendingApprovals,
    api.listPendingApprovals,
    { revalidateOnFocus: false },
  );

  const [saving, setSaving] = useState(false);
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());

  const enforce = config?.enforce ?? false;
  const seuil = (config?.seuil as 'low' | 'medium' | 'high') ?? 'high';

  async function saveConfig(next: GateConfig) {
    setSaving(true);
    // Optimistic: reflect the new policy immediately, revalidate after.
    await mutateConfig(next, { revalidate: false });
    try {
      const saved = await api.setGateConfig(next);
      await mutateConfig(saved, { revalidate: false });
      toast({
        title: saved.enforce ? 'Enforce mode on' : 'Enforce mode off',
        description: saved.enforce
          ? `Risky calls (threshold: ${saved.seuil}) are now held for approval.`
          : 'Detection only — every call is relayed bit-exact.',
        severity: 'info',
      });
    } catch (err) {
      // Roll back to the persisted truth on failure.
      await mutateConfig();
      toast({
        title: 'Could not update gate policy',
        description: String(err),
        severity: 'high',
      });
    } finally {
      setSaving(false);
    }
  }

  async function decide(item: PendingApproval, decision: 'approve' | 'deny') {
    setBusyIds((prev) => new Set(prev).add(item.id));
    try {
      if (decision === 'approve') {
        await api.approveCall(item.id);
      } else {
        await api.denyCall(item.id);
      }
      // Optimistically drop the row, then revalidate against the backend.
      await mutatePending(
        (prev) => (prev ?? []).filter((p) => p.id !== item.id),
        { revalidate: true },
      );
      toast({
        title: decision === 'approve' ? 'Call approved' : 'Call denied',
        description:
          item.tool != null
            ? `${decision === 'approve' ? 'Released' : 'Blocked'} tool "${item.tool}".`
            : undefined,
        severity: 'info',
      });
    } catch (err) {
      toast({
        title: `Could not ${decision} call`,
        description: String(err),
        severity: 'high',
      });
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(item.id);
        return next;
      });
    }
  }

  const queue = [...(pending ?? [])].sort(
    (a, b) => severityRank(b.risk_level) - severityRank(a.risk_level),
  );

  return (
    <section className="card flex flex-col gap-6" aria-label="Approve before run">
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-sentinel-border bg-sentinel-inset">
          <Lock className="h-4.5 w-4.5 text-sentinel-text-secondary" aria-hidden />
        </div>
        <div className="min-w-0">
          <h3 className="text-title text-sentinel-text-primary">Approve before run</h3>
          <p className="mt-1 max-w-prose text-caption text-sentinel-text-secondary">
            Hold risky tool calls until you approve them — instead of finding out
            after the fact.
          </p>
        </div>
      </div>

      {/* Enforce policy */}
      {configError ? (
        <div
          className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-caption text-sentinel-critical"
          role="alert"
        >
          Failed to load the gate policy: {String(configError)}
        </div>
      ) : (
        <div className="rounded-lg border border-sentinel-border bg-sentinel-inset p-4">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-body font-medium text-sentinel-text-primary">
                  Enforce mode
                </span>
                <span
                  className={clsx(
                    'badge',
                    enforce ? 'badge-accent' : 'badge-neutral',
                  )}
                >
                  {enforce ? 'Blocking' : 'Detection only'}
                </span>
              </div>
              <p className="mt-1 max-w-prose text-caption text-sentinel-text-secondary">
                Off: every call is relayed bit-exact and risky ones are only
                flagged — zero friction, no protection. On: calls at or above the
                threshold are held until you decide, trading a little latency for
                a chance to stop an exfiltration before it happens.
              </p>
            </div>
            <Toggle
              checked={enforce}
              disabled={saving || configLoading}
              ariaLabel="Toggle enforce mode"
              onChange={(v) => void saveConfig({ enforce: v, seuil })}
            />
          </div>

          {/* Threshold — only meaningful while enforcing. */}
          <div
            className={clsx(
              'mt-4 border-t border-sentinel-border-soft pt-4 transition-opacity duration-150',
              enforce ? 'opacity-100' : 'opacity-50',
            )}
          >
            <div className="section-heading mb-2">Risk threshold</div>
            <div className="flex flex-wrap items-center gap-2">
              {SEUILS.map((opt) => {
                const active = seuil === opt.value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    disabled={!enforce || saving}
                    title={opt.hint}
                    onClick={() =>
                      void saveConfig({ enforce, seuil: opt.value })
                    }
                    className={clsx(
                      'btn btn-sm',
                      active && 'btn-primary',
                    )}
                    aria-pressed={active}
                  >
                    {opt.label}
                  </button>
                );
              })}
              <span className="text-caption text-sentinel-text-tertiary">
                {SEUILS.find((s) => s.value === seuil)?.hint}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Pending queue */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="section-heading">
            Pending approvals
            {queue.length > 0 && (
              <span className="ml-2 text-sentinel-text-secondary tabular-nums">
                ({queue.length})
              </span>
            )}
          </div>
        </div>

        {pendingError ? (
          <div
            className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-caption text-sentinel-critical"
            role="alert"
          >
            Failed to load the approval queue: {String(pendingError)}
          </div>
        ) : pendingLoading && !pending ? (
          <div className="flex items-center justify-center gap-2 py-8 text-caption text-sentinel-text-secondary">
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            Loading approval queue…
          </div>
        ) : queue.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-sentinel-border py-10 text-center">
            <ShieldCheck className="h-6 w-6 text-sentinel-ok" aria-hidden />
            <p className="text-body text-sentinel-text-secondary">
              No pending approvals
            </p>
            <p className="max-w-prose text-caption text-sentinel-text-tertiary">
              {enforce
                ? 'Nothing is being held right now — all recent calls cleared the threshold.'
                : 'Enforce mode is off, so no calls are being held. Turn it on to start gating risky calls.'}
            </p>
          </div>
        ) : (
          <ul className="flex flex-col gap-2">
            {queue.map((item) => {
              const busy = busyIds.has(item.id);
              return (
                <li
                  key={item.id}
                  className="rounded-lg border border-sentinel-border bg-sentinel-inset p-4"
                >
                  <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={item.risk_level} />
                        {item.held ? (
                          <span className="badge badge-critical">Held</span>
                        ) : (
                          <span className="badge badge-neutral">Advisory</span>
                        )}
                        <span className="font-mono text-caption text-sentinel-text-primary">
                          {item.tool ?? '—'}
                        </span>
                        <span className="text-caption text-sentinel-text-tertiary">
                          server{' '}
                          <span
                            className="font-mono"
                            title={item.server_id}
                          >
                            {shortId(item.server_id)}
                          </span>
                        </span>
                        <span className="text-caption text-sentinel-text-tertiary tabular-nums">
                          · {formatRequestedAt(item.requested_at)}
                        </span>
                      </div>
                      <p className="mt-2 max-w-prose text-caption text-sentinel-text-secondary">
                        {item.reason}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <button
                        type="button"
                        className="btn btn-sm btn-primary"
                        disabled={busy}
                        onClick={() => void decide(item, 'approve')}
                      >
                        {busy ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                        ) : (
                          <Check className="h-3.5 w-3.5" aria-hidden />
                        )}
                        Approve
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm btn-danger"
                        disabled={busy}
                        onClick={() => void decide(item, 'deny')}
                      >
                        <X className="h-3.5 w-3.5" aria-hidden />
                        Deny
                      </button>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}

/* ── Local toggle — same shape as the inline toggles in Settings. ── */
interface ToggleProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  ariaLabel?: string;
}

function Toggle({ checked, onChange, disabled, ariaLabel }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx(
        'relative inline-flex h-[26px] w-[44px] shrink-0 items-center rounded-pill transition-colors duration-200',
        'focus-visible:outline-none focus-visible:shadow-focus',
        checked
          ? 'bg-sentinel-accent'
          : 'bg-white/10 border border-sentinel-border-strong',
        disabled && 'opacity-40 cursor-not-allowed',
      )}
    >
      <span
        className={clsx(
          'inline-block h-[20px] w-[20px] rounded-full bg-white shadow-md transition-transform duration-200',
          checked ? 'translate-x-[20px]' : 'translate-x-[3px]',
        )}
      />
    </button>
  );
}

// ServerDetailDrawer — frosted-glass right-side drawer with full server detail.
// Implemented by Agent UI-9, footer wiring + live probe by Agent W11.

import { useEffect, useMemo, useState } from 'react';
import useSWR, { mutate as globalMutate } from 'swr';
import clsx from 'clsx';
import {
  X,
  ShieldCheck,
  Search,
  Ban,
  ArrowUpRight,
  AlertTriangle,
  Loader2,
  Copy,
  Check,
} from 'lucide-react';

import { api } from '../api/tauri';
import {
  COMMANDS,
  type ApprovalDecision,
  type ProbeResult,
  type ServerDetail,
  type ServerStatus,
  type Tool,
} from '../api/contract';
import ToolList from './ToolList';

export interface ServerDetailDrawerProps {
  serverId: string | null;
  onClose: () => void;
}

const STATUS_LABEL: Record<ServerStatus, string> = {
  approved: 'Approved',
  unknown: 'Unknown',
  suspect: 'Suspect',
  to_investigate: 'Investigate',
  blocked: 'Blocked',
};

// Substrings that, when seen in any tool description, indicate a likely
// poisoning attempt. Kept in sync with ToolList.tsx.
const POISONING_PATTERNS = ['[SYSTEM]', '.env', '~/.ssh', 'id_rsa'] as const;

function hasPoisoning(tools: Tool[]): boolean {
  return tools.some((tool) => {
    const desc = tool.description ?? '';
    return POISONING_PATTERNS.some((needle) => desc.includes(needle));
  });
}

function formatAppleDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const month = d.toLocaleString('en-US', { month: 'short' });
  const day = d.getDate();
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${month} ${day}, ${hh}:${mm}`;
}

// Truncate a long fingerprint by keeping head and tail with ellipsis in middle.
function truncateMiddle(value: string, head = 10, tail = 8): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

// Best-effort derive a probe name from the server endpoint string.
// Examples:
//   "filesystem-server (stdio)" → "filesystem-server"
//   "http://127.0.0.1:8080/mcp" → "http://127.0.0.1:8080/mcp"
function deriveServerName(endpoint: string): string {
  const match = endpoint.match(/^(.*?)\s*\((?:stdio|http)\)\s*$/i);
  return match ? match[1].trim() : endpoint;
}

export default function ServerDetailDrawer({
  serverId,
  onClose,
}: ServerDetailDrawerProps) {
  const open = serverId !== null;

  // SWR key — null when closed so we don't fetch. Tuple keyed so multiple
  // drawer detail entries can coexist in cache.
  const swrKey = open ? [COMMANDS.getServerDetail, serverId] : null;
  const { data, isLoading, mutate } = useSWR<ServerDetail>(
    swrKey,
    () => api.getServerDetail(serverId as string),
  );

  // Per-decision loading state — only one action runs at a time.
  const [busy, setBusy] = useState<ApprovalDecision['decision'] | null>(null);

  // Live probe state.
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);

  // Copy-fingerprint feedback.
  const [copied, setCopied] = useState(false);

  // Reset transient state whenever the drawer switches servers.
  useEffect(() => {
    setProbeResult(null);
    setProbeError(null);
    setCopied(false);
  }, [serverId]);

  // Close on Escape.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  // Lock body scroll while open.
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  const dotClass = useMemo(() => {
    const color = data?.server.color;
    if (color === 'green') return 'dot-green';
    if (color === 'red') return 'dot-red';
    return 'dot-orange';
  }, [data]);

  const server = data?.server;
  const tools = data?.tools ?? [];
  const openFindings = data?.open_findings ?? 0;
  const poisonSuspected = useMemo(() => hasPoisoning(tools), [tools]);

  if (!open) return null;

  const handleApproval = async (decision: ApprovalDecision['decision']) => {
    if (!serverId || busy) return;
    setBusy(decision);
    try {
      await api.applyApproval(serverId, {
        decision,
        operator: 'operator@local',
      });
      // Refresh the drawer's own data plus any other consumer of those keys
      // (Inventory grid, Approvals queue, Overview tiles).
      await Promise.all([
        mutate(),
        globalMutate(COMMANDS.getServerDetail),
        globalMutate(COMMANDS.listServers),
      ]);
    } catch (err) {
      console.error('[ServerDetailDrawer] applyApproval failed', err);
    } finally {
      setBusy(null);
    }
  };

  const handleProbe = async () => {
    if (!server || probing) return;
    setProbing(true);
    setProbeError(null);
    try {
      const result = await api.probeServer({
        name: deriveServerName(server.endpoint),
        transport: server.transport,
        // Detail payload doesn't carry the spawn command — backend probe
        // falls back to its registered launcher when these are null/empty.
        package: null,
        scopes: [],
        command: null,
        args: [],
      });
      setProbeResult(result);
    } catch (err) {
      console.error('[ServerDetailDrawer] probeServer failed', err);
      setProbeError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbing(false);
    }
  };

  const handleCopyFingerprint = async () => {
    const fp = server?.current_fingerprint;
    if (!fp) return;
    try {
      await navigator.clipboard.writeText(fp);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch (err) {
      console.error('[ServerDetailDrawer] clipboard write failed', err);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50"
      role="dialog"
      aria-modal="true"
      aria-label="Server detail"
    >
      {/* Dim + blur overlay */}
      <button
        type="button"
        aria-label="Close drawer"
        onClick={onClose}
        className="absolute inset-0 bg-black/45 backdrop-blur-md animate-fade-up"
        style={{ animationDuration: '200ms' }}
      />

      {/* Panel */}
      <aside
        className="glass-strong absolute right-0 top-0 h-full w-[480px] max-w-full flex flex-col"
        style={{
          animation: 'drawerSlideIn 280ms cubic-bezier(0.2, 0, 0, 1) both',
        }}
      >
        <style>{`
          @keyframes drawerSlideIn {
            0% { transform: translateX(100%); opacity: 0; }
            100% { transform: translateX(0); opacity: 1; }
          }
        `}</style>

        {/* Header */}
        <header className="flex items-start gap-3 p-5 border-b border-white/[0.08]">
          <span
            className={clsx('dot mt-2.5 shrink-0', dotClass)}
            aria-hidden
          />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-[15px] font-semibold text-sentinel-text-primary truncate">
              {server?.endpoint ?? (isLoading ? 'Loading…' : '—')}
            </div>
            <div className="mt-1.5 flex items-center gap-2">
              {server && (
                <>
                  <span
                    className={clsx(
                      'pill',
                      server.transport === 'http'
                        ? 'pill-blue'
                        : 'pill-green',
                    )}
                  >
                    {server.transport}
                  </span>
                  <span
                    className={clsx(
                      'pill',
                      server.color === 'green'
                        ? 'pill-green'
                        : server.color === 'red'
                          ? 'pill-red'
                          : 'pill-orange',
                    )}
                  >
                    {STATUS_LABEL[server.status]}
                  </span>
                </>
              )}
            </div>
          </div>
          <button
            type="button"
            className="btn no-drag !px-2 !py-2"
            onClick={onClose}
            aria-label="Close"
            title="Close"
          >
            <X size={16} />
          </button>
        </header>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
          {/* Poisoning banner — top of drawer, sticks just below header */}
          {poisonSuspected && (
            <section
              className="rounded-glass border border-sentinel-red/60 bg-sentinel-red/10 p-4 shadow-glow-red animate-fade-up"
              role="alert"
            >
              <div className="flex items-start gap-3">
                <AlertTriangle
                  size={16}
                  className="shrink-0 mt-0.5 text-sentinel-red"
                  aria-hidden
                />
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-semibold text-sentinel-text-primary">
                    Poisoning suspect
                  </div>
                  <p className="mt-1 text-[12px] leading-relaxed text-sentinel-text-secondary">
                    One or more tool descriptions contain prompt-injection
                    indicators. Confirm by re-fetching the live tool list.
                  </p>
                  <div className="mt-2 flex items-center gap-3">
                    <button
                      type="button"
                      onClick={handleProbe}
                      disabled={probing}
                      className="no-drag inline-flex items-center gap-1.5 text-[12px] font-medium text-sentinel-red hover:underline disabled:opacity-60 disabled:no-underline"
                    >
                      {probing ? (
                        <>
                          <Loader2
                            size={12}
                            className="animate-spin"
                            aria-hidden
                          />
                          Probing…
                        </>
                      ) : (
                        <>Run live probe</>
                      )}
                    </button>
                    {probeResult && (
                      <span className="text-[11px] text-sentinel-text-tertiary">
                        {probeResult.tool_count}{' '}
                        {probeResult.tool_count === 1 ? 'tool' : 'tools'} ·{' '}
                        {probeResult.poisoning_findings.length} poisoning
                        {probeResult.poisoning_findings.length === 1
                          ? ' finding'
                          : ' findings'}
                      </span>
                    )}
                  </div>
                  {probeError && (
                    <div className="mt-2 text-[11px] text-sentinel-red">
                      Probe failed: {probeError}
                    </div>
                  )}
                  {probeResult &&
                    probeResult.poisoning_findings.length > 0 && (
                      <ul className="mt-3 flex flex-col gap-1.5">
                        {probeResult.poisoning_findings.map((f, idx) => (
                          <li
                            key={`${f.pattern}-${idx}`}
                            className="rounded-md bg-black/30 px-2.5 py-1.5 text-[11px] font-mono text-sentinel-text-secondary"
                          >
                            <span className="text-sentinel-red">
                              {f.severity}
                            </span>{' '}
                            · {f.category} ·{' '}
                            <span className="text-sentinel-text-primary">
                              {f.pattern}
                            </span>
                            {f.excerpt && (
                              <div className="mt-0.5 text-sentinel-text-tertiary truncate">
                                {f.excerpt}
                              </div>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                </div>
              </div>
            </section>
          )}

          {isLoading && !data ? (
            <>
              <div className="card">
                <div className="skeleton h-4 w-1/3 mb-3" />
                <div className="skeleton h-3 w-2/3 mb-2" />
                <div className="skeleton h-3 w-1/2" />
              </div>
              <div className="card">
                <div className="skeleton h-4 w-1/4 mb-3" />
                <div className="skeleton h-3 w-3/4 mb-2" />
                <div className="skeleton h-3 w-2/3" />
              </div>
            </>
          ) : (
            <>
              {/* At a glance */}
              <section className="card animate-fade-up">
                <div className="section-heading mb-3">At a glance</div>
                <div className="grid grid-cols-2 gap-4 text-[12px]">
                  <div>
                    <div className="text-sentinel-text-tertiary mb-1">
                      Tools
                    </div>
                    <div className="text-sentinel-text-primary font-semibold text-[15px]">
                      {server?.tool_count ?? tools.length}
                    </div>
                  </div>
                  <div>
                    <div className="text-sentinel-text-tertiary mb-1">
                      Fingerprint
                    </div>
                    <div className="flex items-center gap-1.5 min-w-0">
                      <div
                        className="font-mono text-[12px] text-sentinel-text-secondary truncate"
                        title={server?.current_fingerprint ?? ''}
                      >
                        {server?.current_fingerprint
                          ? truncateMiddle(server.current_fingerprint)
                          : '—'}
                      </div>
                      {server?.current_fingerprint && (
                        <button
                          type="button"
                          onClick={handleCopyFingerprint}
                          className="no-drag inline-flex items-center justify-center rounded-md p-1 text-sentinel-text-tertiary hover:text-sentinel-text-primary hover:bg-white/[0.06] transition-colors"
                          aria-label={
                            copied
                              ? 'Fingerprint copied'
                              : 'Copy fingerprint to clipboard'
                          }
                          title={copied ? 'Copied!' : 'Copy fingerprint'}
                        >
                          {copied ? (
                            <Check size={12} className="text-sentinel-green" />
                          ) : (
                            <Copy size={12} />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-sentinel-text-tertiary mb-1">
                      First seen
                    </div>
                    <div className="text-sentinel-text-secondary">
                      {server ? formatAppleDate(server.first_seen) : '—'}
                    </div>
                  </div>
                  <div>
                    <div className="text-sentinel-text-tertiary mb-1">
                      Last seen
                    </div>
                    <div className="text-sentinel-text-secondary">
                      {server ? formatAppleDate(server.last_seen) : '—'}
                    </div>
                  </div>
                </div>

                {server && server.scopes.length > 0 && (
                  <div className="mt-4">
                    <div className="section-heading mb-2">Scopes</div>
                    <div className="flex flex-wrap gap-1.5">
                      {server.scopes.map((s) => (
                        <span
                          key={s}
                          className="rounded-pill px-2 py-0.5 text-[10px] font-medium tracking-wide uppercase bg-white/[0.06] text-sentinel-text-secondary border border-white/10"
                        >
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </section>

              {/* Tools */}
              <section className="card animate-fade-up">
                <div className="flex items-center justify-between mb-3">
                  <div className="section-heading">Tools</div>
                  <div className="text-[11px] text-sentinel-text-tertiary">
                    {tools.length} {tools.length === 1 ? 'tool' : 'tools'}
                  </div>
                </div>
                <ToolList tools={tools} />
              </section>

              {/* Open findings */}
              <section className="card animate-fade-up">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="section-heading">Open findings</div>
                    <span
                      className={clsx(
                        'pill',
                        openFindings === 0
                          ? 'pill-green'
                          : openFindings > 2
                            ? 'pill-red'
                            : 'pill-orange',
                      )}
                    >
                      {openFindings}
                    </span>
                  </div>
                  <a
                    href="#/alerts"
                    className="inline-flex items-center gap-1 text-[12px] text-sentinel-blue-glow hover:underline no-drag"
                  >
                    Go to alerts
                    <ArrowUpRight size={13} />
                  </a>
                </div>
              </section>
            </>
          )}
        </div>

        {/* Sticky footer — Quick actions */}
        <footer className="glass-soft border-t border-white/[0.08] p-4 flex items-center gap-2">
          <button
            type="button"
            className="btn btn-primary no-drag flex-1 justify-center"
            disabled={busy !== null || !serverId}
            onClick={() => handleApproval('approve')}
          >
            {busy === 'approve' ? (
              <Loader2 size={14} className="animate-spin" aria-hidden />
            ) : (
              <ShieldCheck size={14} />
            )}
            Approve
          </button>
          <button
            type="button"
            className="btn no-drag flex-1 justify-center"
            disabled={busy !== null || !serverId}
            onClick={() => handleApproval('investigate')}
          >
            {busy === 'investigate' ? (
              <Loader2 size={14} className="animate-spin" aria-hidden />
            ) : (
              <Search size={14} />
            )}
            Investigate
          </button>
          <button
            type="button"
            className="btn btn-danger no-drag flex-1 justify-center"
            disabled={busy !== null || !serverId}
            onClick={() => handleApproval('block')}
          >
            {busy === 'block' ? (
              <Loader2 size={14} className="animate-spin" aria-hidden />
            ) : (
              <Ban size={14} />
            )}
            Block
          </button>
        </footer>
      </aside>
    </div>
  );
}

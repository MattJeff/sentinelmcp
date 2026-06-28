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
  ChevronDown,
} from 'lucide-react';

import { api } from '../api/tauri';
import {
  COMMANDS,
  type ApprovalDecision,
  type DiscoveredClient,
  type DiscoveredClientKind,
  type DiscoveryReport,
  type EnforcementRemoveResult,
  type Finding,
  type Investigation,
  type ProbeResult,
  type ServerDetail,
  type ServerStatus,
  type Settings,
  type Tool,
} from '../api/contract';
import ToolList from './ToolList';
import DiffViewer from './DiffViewer';
import { CategoryBadge, ComplianceRefBadges } from '../lib/findingCategory';
import InvestigateDialog, {
  subscribeInvestigations,
} from './InvestigateDialog';
import EnforcementConfirmDialog from './EnforcementConfirmDialog';
import TagsEditor from './TagsEditor';
import { useToastStore } from '../hooks/useToast';

interface DeclaringClient {
  kind: DiscoveredClientKind;
  configPath: string | null;
}

/**
 * Walk the Discovery snapshot to find which AI client declares `endpoint`.
 * Mirrors the helper used on the Approvals page.
 */
function findDeclaringClient(
  report: DiscoveryReport | undefined,
  endpoint: string,
): DeclaringClient | null {
  if (!report) return null;
  const needle = deriveServerName(endpoint).toLowerCase();
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

  // Surface the enforcement toggle + Discovery snapshot so the Block button
  // knows whether to escalate to the rewrite dialog and which config to
  // surface in it.
  const { data: settings } = useSWR<Settings>(
    COMMANDS.getSettings,
    () => api.getSettings(),
  );
  const { data: discovery } = useSWR<DiscoveryReport>(
    COMMANDS.discoverSystem,
    () => api.discoverSystem(),
  );
  const enforcementEnabled = settings?.enforcement?.enabled ?? false;

  // Open findings for this server — so the drawer can surface each finding's
  // attack category, compliance refs, and (for rug-pull/drift) the actual
  // before/after diff inline. `listFindings` returns every open finding; we
  // filter client-side by server id. Keyed without the id so switching server
  // reuses the cached list instead of refetching.
  const { data: allFindings } = useSWR<Finding[]>(
    open ? [COMMANDS.listFindings, 'drawer'] : null,
    () => api.listFindings(false),
  );
  const serverFindings = useMemo(
    () => (allFindings ?? []).filter((f) => f.server_id === serverId),
    [allFindings, serverId],
  );

  // Live probe state.
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);

  // Copy-fingerprint feedback.
  const [copied, setCopied] = useState(false);

  // Investigate dialog target + past investigation entries for this server.
  const [investigateOpen, setInvestigateOpen] = useState(false);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);

  // Enforcement dialog state — only meaningful when `enforcementEnabled`.
  const [enforceOpen, setEnforceOpen] = useState(false);
  const [lastBackup, setLastBackup] = useState<EnforcementRemoveResult | null>(
    null,
  );
  const [restoring, setRestoring] = useState(false);

  // Tag editor state — local draft kept in sync with the server payload so
  // the operator can edit then explicitly Save.
  const [tagsDraft, setTagsDraft] = useState<string[]>([]);
  const [tagSuggestions, setTagSuggestions] = useState<string[]>([]);
  const [savingTags, setSavingTags] = useState(false);

  const pushToast = useToastStore((s) => s.push);

  // Reset transient state whenever the drawer switches servers.
  useEffect(() => {
    setProbeResult(null);
    setProbeError(null);
    setCopied(false);
    setInvestigateOpen(false);
    setEnforceOpen(false);
    setLastBackup(null);
    setSavingTags(false);
  }, [serverId]);

  // Hydrate the tag draft from the latest server payload. Re-running on
  // every detail refresh keeps the editor in sync after Save, without
  // clobbering an in-flight edit on the same server (we only reset when
  // the underlying server id flips).
  useEffect(() => {
    setTagsDraft(data?.server.tags ?? []);
  }, [serverId, data?.server.tags]);

  // Load the autocomplete pool once per open. Refresh after Save so newly
  // minted tags surface on the next edit.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    api
      .serverListTags()
      .then((all) => {
        if (!cancelled) setTagSuggestions(all);
      })
      .catch((err) => {
        console.error('[ServerDetailDrawer] serverListTags failed', err);
      });
    return () => {
      cancelled = true;
    };
  }, [open, serverId]);

  // Load past investigation notes whenever the drawer opens on a new server,
  // and refresh on every store update (e.g. after the dialog records one).
  useEffect(() => {
    if (!serverId) {
      setInvestigations([]);
      return;
    }
    let cancelled = false;
    const refresh = () => {
      api
        .listInvestigations(serverId)
        .then((entries) => {
          if (!cancelled) setInvestigations(entries);
        })
        .catch((err) => {
          console.error('[ServerDetailDrawer] listInvestigations failed', err);
          if (!cancelled) setInvestigations([]);
        });
    };
    refresh();
    const unsubscribe = subscribeInvestigations(refresh);
    return () => {
      cancelled = true;
      unsubscribe();
    };
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
    if (color === 'green') return 'dot-ok';
    if (color === 'red') return 'dot-critical';
    return 'dot-high';
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

  const handleSaveTags = async () => {
    if (!serverId || savingTags) return;
    setSavingTags(true);
    try {
      await api.serverSetTags(serverId, tagsDraft);
      pushToast({
        title: 'Tags saved',
        description: `${tagsDraft.length} tag${tagsDraft.length === 1 ? '' : 's'} on this server`,
        severity: 'info',
      });
      // Refresh the autocomplete pool and the detail / inventory caches so
      // the new chips show up everywhere without reloading the app.
      const [refreshed] = await Promise.all([
        api.serverListTags().catch(() => tagSuggestions),
        mutate(),
        globalMutate(COMMANDS.listServers),
      ]);
      setTagSuggestions(refreshed);
    } catch (err) {
      console.error('[ServerDetailDrawer] serverSetTags failed', err);
      pushToast({
        title: 'Failed to save tags',
        description: err instanceof Error ? err.message : String(err),
        severity: 'high',
      });
    } finally {
      setSavingTags(false);
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
        className="absolute inset-0 bg-black/50 backdrop-blur-xs animate-fade-up"
        style={{ animationDuration: '200ms' }}
      />

      {/* Panel */}
      <aside
        className="surface-raised shadow-raised absolute right-0 top-0 h-full w-[480px] max-w-full flex flex-col"
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
        <header className="flex items-start gap-3 p-6 border-b border-sentinel-border-soft">
          <span
            className={clsx('dot mt-2 shrink-0', dotClass)}
            aria-hidden
          />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-title text-sentinel-text-primary truncate">
              {server?.endpoint ?? (isLoading ? 'Loading…' : '—')}
            </div>
            <div className="mt-2 flex items-center gap-2">
              {server && (
                <>
                  <span className="badge badge-neutral">
                    {server.transport}
                  </span>
                  <span
                    className={clsx(
                      'badge',
                      server.color === 'green'
                        ? 'badge-ok'
                        : server.color === 'red'
                          ? 'badge-critical'
                          : 'badge-high',
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
        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4">
          {/* Poisoning banner — top of drawer, sticks just below header */}
          {poisonSuspected && (
            <section
              className="rounded-glass border border-sentinel-critical-border bg-sentinel-critical-bg border-l-2 border-l-sentinel-critical p-4 animate-fade-up"
              role="alert"
            >
              <div className="flex items-start gap-3">
                <AlertTriangle
                  size={16}
                  className="shrink-0 mt-1 text-sentinel-critical"
                  aria-hidden
                />
                <div className="flex-1 min-w-0">
                  <div className="text-body font-semibold text-sentinel-text-primary">
                    Poisoning suspect
                  </div>
                  <p className="mt-1 text-caption leading-relaxed text-sentinel-text-secondary">
                    One or more tool descriptions contain prompt-injection
                    indicators. Confirm by re-fetching the live tool list.
                  </p>
                  <div className="mt-2 flex items-center gap-3">
                    <button
                      type="button"
                      onClick={handleProbe}
                      disabled={probing}
                      className="no-drag inline-flex items-center gap-2 text-caption font-medium text-sentinel-critical hover:underline disabled:opacity-40 disabled:no-underline focus-visible:outline-none focus-visible:shadow-focus rounded-lg"
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
                      <span className="text-caption text-sentinel-text-tertiary tabular-nums">
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
                    <div className="mt-2 text-caption text-sentinel-critical">
                      Probe failed: {probeError}
                    </div>
                  )}
                  {probeResult &&
                    probeResult.poisoning_findings.length > 0 && (
                      <ul className="mt-3 flex flex-col gap-2">
                        {probeResult.poisoning_findings.map((f, idx) => (
                          <li
                            key={`${f.pattern}-${idx}`}
                            className="rounded-lg bg-sentinel-inset border border-sentinel-border-soft px-3 py-2 font-mono text-caption text-sentinel-text-secondary"
                          >
                            <span className="text-sentinel-critical">
                              {f.severity}
                            </span>{' '}
                            · {f.category} ·{' '}
                            <span className="text-sentinel-text-primary">
                              {f.pattern}
                            </span>
                            {f.excerpt && (
                              <div className="mt-1 text-sentinel-text-tertiary truncate">
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
                <div className="section-heading mb-4">At a glance</div>
                <div className="grid grid-cols-2 gap-4 text-caption">
                  <div>
                    <div className="text-overline text-sentinel-text-tertiary mb-1">
                      Tools
                    </div>
                    <div className="text-metric text-sentinel-text-primary tabular-nums">
                      {server?.tool_count ?? tools.length}
                    </div>
                  </div>
                  <div>
                    <div className="text-overline text-sentinel-text-tertiary mb-1">
                      Fingerprint
                    </div>
                    <div className="flex items-center gap-2 min-w-0">
                      <div
                        className="font-mono text-caption text-sentinel-text-secondary truncate"
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
                          className="no-drag inline-flex items-center justify-center rounded-lg p-1 text-sentinel-text-tertiary hover:text-sentinel-text-primary hover:bg-sentinel-inset transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus"
                          aria-label={
                            copied
                              ? 'Fingerprint copied'
                              : 'Copy fingerprint to clipboard'
                          }
                          title={copied ? 'Copied!' : 'Copy fingerprint'}
                        >
                          {copied ? (
                            <Check size={12} className="text-sentinel-ok" />
                          ) : (
                            <Copy size={12} />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-overline text-sentinel-text-tertiary mb-1">
                      First seen
                    </div>
                    <div className="text-sentinel-text-secondary tabular-nums">
                      {server ? formatAppleDate(server.first_seen) : '—'}
                    </div>
                  </div>
                  <div>
                    <div className="text-overline text-sentinel-text-tertiary mb-1">
                      Last seen
                    </div>
                    <div className="text-sentinel-text-secondary tabular-nums">
                      {server ? formatAppleDate(server.last_seen) : '—'}
                    </div>
                  </div>
                  <div className="col-span-2">
                    <div className="text-overline text-sentinel-text-tertiary mb-1">
                      Scope
                    </div>
                    <div className="text-sentinel-text-secondary">
                      {!server || !server.scope ? (
                        '—'
                      ) : server.scope.kind === 'user' ? (
                        'User'
                      ) : (
                        <>
                          <span>Project — </span>
                          <span
                            className="font-mono text-caption text-sentinel-text-primary break-all"
                            title={server.scope.path}
                          >
                            {server.scope.path}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                {server && server.scopes.length > 0 && (
                  <div className="mt-6">
                    <div className="section-heading mb-2">Scopes</div>
                    <div className="flex flex-wrap gap-2">
                      {server.scopes.map((s) => (
                        <span
                          key={s}
                          className="rounded-pill px-2 py-0.5 text-[11px] font-medium bg-sentinel-inset text-sentinel-text-tertiary border border-sentinel-border-soft"
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
                <div className="flex items-center justify-between mb-4">
                  <div className="section-heading">Tools</div>
                  <div className="text-caption text-sentinel-text-tertiary tabular-nums">
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
                        'badge tabular-nums',
                        openFindings === 0
                          ? 'badge-ok'
                          : openFindings > 2
                            ? 'badge-critical'
                            : 'badge-high',
                      )}
                    >
                      {openFindings}
                    </span>
                  </div>
                  <a
                    href="#/alerts"
                    className="inline-flex items-center gap-1 text-caption text-sentinel-accent hover:underline no-drag focus-visible:outline-none focus-visible:shadow-focus rounded-lg"
                  >
                    Go to alerts
                    <ArrowUpRight size={13} />
                  </a>
                </div>

                {serverFindings.length > 0 && (
                  <ul className="mt-4 flex flex-col gap-3">
                    {serverFindings.map((f) => (
                      <li
                        key={f.id}
                        className="rounded-lg border border-sentinel-border bg-sentinel-inset p-3"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <CategoryBadge
                            severity={f.severity}
                            finding_type={f.finding_type}
                            title={f.title}
                            detail={f.detail}
                            diff={f.diff}
                            compliance_refs={f.compliance_refs}
                          />
                          <span className="text-caption font-semibold text-sentinel-text-primary">
                            {f.title}
                          </span>
                        </div>
                        {f.detail && (
                          <p className="mt-2 text-caption leading-relaxed text-sentinel-text-secondary">
                            {f.detail}
                          </p>
                        )}
                        <ComplianceRefBadges refs={f.compliance_refs} className="mt-2" />
                        {f.diff && (
                          <details className="mt-3 group">
                            <summary className="flex items-center gap-1.5 cursor-pointer list-none text-caption text-sentinel-accent hover:underline no-drag focus-visible:outline-none focus-visible:shadow-focus rounded-lg">
                              <ChevronDown
                                size={13}
                                aria-hidden
                                className="shrink-0 transition-transform duration-200 group-open:rotate-180"
                              />
                              View change diff (before → after)
                            </summary>
                            <div className="mt-2 max-w-full overflow-x-auto">
                              <DiffViewer diff={f.diff} />
                            </div>
                          </details>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {/* Tags — operator-curated labels persisted on the server row */}
              <section className="card animate-fade-up">
                <div className="flex items-center justify-between mb-4">
                  <div className="section-heading">Tags</div>
                  <button
                    type="button"
                    onClick={handleSaveTags}
                    disabled={savingTags || !serverId}
                    className="text-caption text-sentinel-accent hover:underline no-drag disabled:opacity-40 disabled:no-underline focus-visible:outline-none focus-visible:shadow-focus rounded-lg"
                    title="Persist these tags on the server row"
                  >
                    {savingTags ? (
                      <span className="inline-flex items-center gap-1">
                        <Loader2 size={12} className="animate-spin" aria-hidden />
                        Saving…
                      </span>
                    ) : (
                      'Save tags'
                    )}
                  </button>
                </div>
                <TagsEditor
                  value={tagsDraft}
                  onChange={setTagsDraft}
                  suggestions={tagSuggestions}
                  disabled={savingTags}
                />
              </section>

              {/* Investigations — past notes attached to this server */}
              <section className="card animate-fade-up">
                <div className="flex items-center justify-between mb-4">
                  <div className="section-heading">
                    Investigations ({investigations.length})
                  </div>
                  <button
                    type="button"
                    className="text-caption text-sentinel-accent hover:underline no-drag focus-visible:outline-none focus-visible:shadow-focus rounded-lg"
                    onClick={() => setInvestigateOpen(true)}
                  >
                    Open new
                  </button>
                </div>
                {investigations.length === 0 ? (
                  <p className="text-caption text-sentinel-text-tertiary">
                    No investigation has been opened on this server yet.
                  </p>
                ) : (
                  <ul className="flex flex-col gap-2">
                    {investigations.map((entry) => (
                      <li
                        key={entry.id}
                        className="rounded-lg border border-sentinel-border bg-sentinel-inset p-3"
                      >
                        <p className="whitespace-pre-wrap text-caption leading-relaxed text-sentinel-text-primary">
                          {entry.note}
                        </p>
                        <div className="mt-2 flex flex-wrap items-center gap-2 text-caption text-sentinel-text-tertiary">
                          <span className="font-medium text-sentinel-text-secondary">
                            {entry.operator ?? entry.created_by}
                          </span>
                          <span aria-hidden>·</span>
                          <time dateTime={entry.created_at}>
                            {formatAppleDate(entry.created_at)}
                          </time>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </>
          )}
        </div>

        {/* Sticky footer — Quick actions */}
        <footer className="glass-soft border-t border-sentinel-border-soft p-4 flex items-center gap-2">
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
            onClick={() => setInvestigateOpen(true)}
          >
            <Search size={14} />
            Investigate
          </button>
          <button
            type="button"
            className="btn btn-danger no-drag flex-1 justify-center"
            disabled={busy !== null || !serverId}
            onClick={() => {
              // Enforcement is opt-in. When enabled, route the Block click
              // through the second-confirmation dialog (config rewrite +
              // backup); otherwise keep the advisory status update.
              if (enforcementEnabled) setEnforceOpen(true);
              else void handleApproval('block');
            }}
          >
            {busy === 'block' ? (
              <Loader2 size={14} className="animate-spin" aria-hidden />
            ) : (
              <Ban size={14} />
            )}
            Block
          </button>
        </footer>
        {lastBackup && (
          <div
            role="status"
            aria-live="polite"
            className="border-t border-sentinel-border-soft px-4 py-2 flex items-center gap-2 text-caption text-sentinel-text-secondary glass-soft"
          >
            <span className="font-mono text-sentinel-text-tertiary truncate flex-1 min-w-0" title={lastBackup.backup_path}>
              Backup: {lastBackup.backup_path}
            </span>
            <button
              type="button"
              className="no-drag text-sentinel-accent hover:underline disabled:opacity-40 shrink-0 focus-visible:outline-none focus-visible:shadow-focus rounded-lg"
              disabled={restoring}
              onClick={async () => {
                if (!lastBackup || restoring) return;
                setRestoring(true);
                try {
                  const r = await api.enforcementRestore(
                    lastBackup.backup_path,
                  );
                  if (r.ok) {
                    pushToast({
                      title: 'Restored from backup',
                      description: r.config_path,
                      severity: 'info',
                    });
                    setLastBackup(null);
                    await Promise.all([
                      mutate(),
                      globalMutate(COMMANDS.getServerDetail),
                      globalMutate(COMMANDS.listServers),
                    ]);
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
                    description:
                      err instanceof Error ? err.message : String(err),
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
      </aside>

      <InvestigateDialog
        serverId={investigateOpen && serverId ? serverId : null}
        endpoint={server?.endpoint ?? null}
        onOpenChange={(next) => setInvestigateOpen(next)}
        onSubmitted={async () => {
          // Refresh the drawer's own detail plus any inventory/approvals
          // consumers, mirroring how `handleApproval` revalidates the cache.
          await Promise.all([
            mutate(),
            globalMutate(COMMANDS.getServerDetail),
            globalMutate(COMMANDS.listServers),
          ]);
        }}
      />

      <EnforcementConfirmDialog
        open={enforceOpen}
        onOpenChange={setEnforceOpen}
        endpoint={server?.endpoint ?? null}
        configPath={
          server ? findDeclaringClient(discovery, server.endpoint)?.configPath ?? null : null
        }
        backupPath={(() => {
          if (!server) return null;
          const cfg = findDeclaringClient(discovery, server.endpoint)?.configPath;
          return cfg ? `${cfg}.sentinel-backup` : null;
        })()}
        onConfirm={async () => {
          if (!serverId || !server) return;
          const declaring = findDeclaringClient(discovery, server.endpoint);
          try {
            const result = await api.enforcementRemoveServer(
              serverId,
              declaring?.kind ?? null,
            );
            setEnforceOpen(false);
            if (result.ok) {
              setLastBackup(result);
              pushToast({
                title: 'Removed from AI client config',
                description: `Config: ${result.config_path} · Backup: ${result.backup_path}`,
                severity: 'info',
              });
              // Mirror the advisory side-effect: mark the server Bloque in
              // Sentinel's own audit trail via the usual approval pipeline.
              await handleApproval('block');
            } else {
              pushToast({
                title: 'Enforcement failed',
                description: result.error ?? 'Unknown error',
                severity: 'high',
              });
            }
          } catch (err) {
            setEnforceOpen(false);
            pushToast({
              title: 'Enforcement failed',
              description: err instanceof Error ? err.message : String(err),
              severity: 'high',
            });
          }
        }}
      />
    </div>
  );
}

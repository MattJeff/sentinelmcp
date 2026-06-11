// ClientCard — one frosted tile per detected AI client, listing the MCP
// servers it declares. Expand to see the per-server ServerRow list.

import { useMemo, useState } from 'react';
import clsx from 'clsx';
import {
  Anchor,
  AlertTriangle,
  Bot,
  ChevronDown,
  ChevronUp,
  Code2,
  Compass,
  Feather,
  Loader2,
  MessageSquareCode,
  MousePointerClick,
  Rocket,
  Search,
  Sparkles,
  SquareTerminal,
  Wind,
  Zap,
  type LucideIcon,
} from 'lucide-react';

import { api } from '@/api/tauri';
import type {
  DiscoveredClient,
  DiscoveredClientKind,
  ProbeResult,
} from '@/api/contract';
import ServerRow from './ServerRow';

const CLIENT_ICON: Record<DiscoveredClientKind, LucideIcon> = {
  'claude-desktop': Anchor,
  'claude-code-cli': SquareTerminal,
  cursor: MousePointerClick,
  windsurf: Wind,
  zed: Zap,
  vscode: Code2,
  continue: MessageSquareCode,
  aider: Feather,
  goose: Bot,
  codex: Sparkles,
  antigravity: Rocket,
  'lm-studio': Compass,
};

export interface ClientCardProps {
  client: DiscoveredClient;
  probes?: ProbeResult[];
  onProbe?: (kind: DiscoveredClientKind) => void;
}

function serverCountTone(n: number): { className: string; label: string } {
  if (n === 0) return { className: 'badge-ok', label: '0 servers' };
  if (n <= 3) return { className: 'badge-medium', label: `${n} ${n === 1 ? 'server' : 'servers'}` };
  return { className: 'badge-high', label: `${n} servers` };
}

export default function ClientCard({ client, probes, onProbe }: ClientCardProps) {
  const Icon = CLIENT_ICON[client.kind] ?? Bot;
  const [expanded, setExpanded] = useState(false);
  const [probing, setProbing] = useState(false);
  // Local probes from the live `probe_server` Tauri command, keyed by name.
  // Overlaid on top of any probes passed in via props so we keep working when
  // the parent later refreshes its discovery report.
  const [localProbes, setLocalProbes] = useState<Record<string, ProbeResult>>(
    {},
  );

  const hasServers = client.servers.length > 0;
  const tertiary = !client.installed;
  const tone = serverCountTone(client.servers.length);

  const probeByName = useMemo(() => {
    const map = new Map<string, ProbeResult>();
    for (const p of probes ?? []) map.set(p.server_name, p);
    for (const [name, p] of Object.entries(localProbes)) map.set(name, p);
    return map;
  }, [probes, localProbes]);

  const poisoningCount = useMemo(() => {
    let n = 0;
    for (const p of probeByName.values()) n += p.poisoning_findings?.length ?? 0;
    return n;
  }, [probeByName]);

  async function handleProbeAll() {
    if (probing) return;
    setProbing(true);
    try {
      // Sequential probing so we don't fork a dozen child processes at once.
      for (const server of client.servers) {
        try {
          const result = await api.probeServer(server);
          // ServerRow still reads the legacy `reachable` flag — derive it from
          // the new `state` so the existing UI keeps working without edits.
          const withCompat: ProbeResult = {
            ...result,
            reachable: result.state === 'success',
            latency_ms: result.duration_ms,
          };
          setLocalProbes((prev) => ({ ...prev, [server.name]: withCompat }));
        } catch (err) {
          // Surface the failure inline as a synthetic "launch_failed" probe so
          // the row still shows an X rather than vanishing silently.
          setLocalProbes((prev) => ({
            ...prev,
            [server.name]: {
              server_name: server.name,
              state: 'launch_failed',
              tool_count: 0,
              fingerprint: null,
              tools: [],
              poisoning_findings: [],
              duration_ms: 0,
              error: String(err),
              reachable: false,
              latency_ms: null,
            },
          }));
        }
      }
      onProbe?.(client.kind);
    } finally {
      setProbing(false);
    }
  }

  return (
    <div
      className={clsx(
        'card-hover animate-fade-up flex flex-col gap-4',
        tertiary && 'opacity-40',
      )}
    >
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className="h-9 w-9 shrink-0 rounded-lg bg-white/6 border border-sentinel-border flex items-center justify-center">
          <Icon className="h-4 w-4 text-sentinel-text-primary" aria-hidden />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-title truncate">
              {client.label}
            </span>
            {client.version && (
              <span className="badge badge-accent">v{client.version}</span>
            )}
            {!client.installed && (
              <span className="badge badge-neutral">
                Not installed
              </span>
            )}
          </div>
          <div className="mt-1 text-caption text-sentinel-text-tertiary truncate">
            {client.installed
              ? client.configs.length > 0
                ? client.configs[0]
                : 'Installed · no config file'
              : 'Known client'}
          </div>
        </div>
      </div>

      {/* Middle: server-count pill + notes */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className={clsx('badge tabular-nums', tone.className)}>
          <span
            className={clsx(
              'dot',
              client.servers.length === 0
                ? 'dot-ok'
                : client.servers.length <= 3
                  ? 'dot-medium'
                  : 'dot-high',
            )}
          />
          {tone.label}
        </span>
        {client.notes.map((n) => (
          <span
            key={n}
            className="badge badge-neutral"
          >
            {n}
          </span>
        ))}
        {poisoningCount > 0 && (
          <span className="badge badge-critical tabular-nums" title="Poisoning patterns detected in live probe responses">
            <AlertTriangle className="h-3 w-3" aria-hidden />
            Poisoning detected · {poisoningCount}
          </span>
        )}
      </div>

      {/* Expandable server list */}
      {hasServers && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-2 rounded-lg text-overline text-sentinel-text-tertiary hover:text-sentinel-text-secondary transition-colors duration-150 self-start focus-visible:outline-none focus-visible:shadow-focus"
          aria-expanded={expanded}
        >
          {expanded ? (
            <ChevronUp className="h-3.5 w-3.5" aria-hidden />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" aria-hidden />
          )}
          {expanded ? 'Hide servers' : 'View servers'}
        </button>
      )}

      {expanded && hasServers && (
        <div className="flex flex-col gap-2 animate-fade-up">
          {client.servers.map((s) => (
            <ServerRow
              key={s.name}
              server={s}
              probe={probeByName.get(s.name) ?? null}
            />
          ))}
        </div>
      )}

      {/* Footer */}
      {client.installed && hasServers && (
        <div className="mt-auto flex justify-end pt-2">
          <button
            type="button"
            className="btn btn-sm disabled:opacity-40 disabled:cursor-not-allowed"
            onClick={handleProbeAll}
            disabled={probing}
            aria-busy={probing}
          >
            {probing ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                Probing…
              </>
            ) : (
              <>
                <Search className="h-3.5 w-3.5" aria-hidden />
                Probe live
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

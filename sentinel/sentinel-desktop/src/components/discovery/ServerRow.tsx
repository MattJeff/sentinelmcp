// ServerRow — one declared MCP server inside a ClientCard.
// Renders the server name, its package, its transport, and any scopes.
// On the right: a status pill ("Not probed" by default, "12 tools" if probed).

import clsx from 'clsx';
import type { DeclaredServer, ProbeResult, Scope } from '@/api/contract';

export interface ServerRowProps {
  server: DeclaredServer;
  probe?: ProbeResult | null;
}

const SCOPE_TONE: Record<Scope, 'green' | 'orange' | 'red' | 'neutral'> = {
  filesystem: 'orange',
  database: 'orange',
  external_api: 'red',
  secrets: 'red',
  network: 'orange',
  read: 'neutral',
  write: 'orange',
  unknown: 'neutral',
};

function scopeClasses(tone: 'green' | 'orange' | 'red' | 'neutral'): string {
  switch (tone) {
    case 'green':
      return 'bg-sentinel-ok-bg text-sentinel-ok border-sentinel-ok-border';
    case 'orange':
      return 'bg-sentinel-medium-bg text-sentinel-medium border-sentinel-medium-border';
    case 'red':
      return 'bg-sentinel-critical-bg text-sentinel-critical border-sentinel-critical-border';
    default:
      return 'bg-white/4 text-sentinel-text-secondary border-sentinel-border';
  }
}

export default function ServerRow({ server, probe }: ServerRowProps) {
  const probed = probe && probe.reachable;
  return (
    <div className="glass-soft flex items-center gap-3 rounded-lg p-3 hover:bg-sentinel-raised hover:border-sentinel-border-strong transition-colors duration-150">
      {/* Left block — name + package */}
      <div className="flex-1 min-w-0">
        <div className="font-mono text-body font-medium text-sentinel-text-primary truncate">
          {server.name}
        </div>
        {server.package && (
          <div className="mt-1 font-mono text-caption text-sentinel-text-tertiary truncate">
            {server.package}
          </div>
        )}
      </div>

      {/* Transport */}
      <span
        className={clsx(
          'badge shrink-0',
          server.transport === 'http' ? 'badge-accent' : 'badge-neutral',
        )}
      >
        {server.transport}
      </span>

      {/* Scopes */}
      {server.scopes.length > 0 && (
        <div className="hidden md:flex shrink-0 flex-wrap gap-1 max-w-[220px] justify-end">
          {server.scopes.map((s) => (
            <span
              key={s}
              className={clsx(
                'inline-flex items-center rounded-pill border px-2 py-0.5 text-caption font-medium',
                scopeClasses(SCOPE_TONE[s] ?? 'neutral'),
              )}
            >
              {s.replace('_', ' ')}
            </span>
          ))}
        </div>
      )}

      {/* Status */}
      <div className="shrink-0 text-right min-w-[88px]">
        {probed ? (
          <span className="badge badge-ok tabular-nums">
            <span className="dot dot-ok" />
            {probe!.tool_count} {probe!.tool_count === 1 ? 'tool' : 'tools'}
          </span>
        ) : probe && !probe.reachable ? (
          <span className="badge badge-critical">
            <span className="dot dot-critical" />
            Unreachable
          </span>
        ) : (
          <span className="text-caption text-sentinel-text-faint">
            Not probed
          </span>
        )}
      </div>
    </div>
  );
}

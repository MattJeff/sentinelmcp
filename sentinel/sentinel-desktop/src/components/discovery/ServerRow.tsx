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
      return 'bg-sentinel-green/12 text-[#b8f5c8] border-sentinel-green/30';
    case 'orange':
      return 'bg-sentinel-orange/12 text-[#ffd8a0] border-sentinel-orange/30';
    case 'red':
      return 'bg-sentinel-red/14 text-[#ffc1ba] border-sentinel-red/35';
    default:
      return 'bg-white/6 text-sentinel-text-secondary border-white/10';
  }
}

export default function ServerRow({ server, probe }: ServerRowProps) {
  const probed = probe && probe.reachable;
  return (
    <div className="glass-soft flex items-center gap-3 rounded-glass px-3.5 py-2.5">
      {/* Left block — name + package */}
      <div className="flex-1 min-w-0">
        <div className="font-mono text-[12.5px] font-semibold text-sentinel-text-primary truncate">
          {server.name}
        </div>
        {server.package && (
          <div className="mt-0.5 font-mono text-[10.5px] text-sentinel-text-tertiary truncate">
            {server.package}
          </div>
        )}
      </div>

      {/* Transport */}
      <span
        className={clsx(
          'pill shrink-0',
          server.transport === 'http' ? 'pill-blue' : 'pill-green',
        )}
      >
        {server.transport}
      </span>

      {/* Scopes */}
      {server.scopes.length > 0 && (
        <div className="hidden md:flex shrink-0 flex-wrap gap-1.5 max-w-[220px] justify-end">
          {server.scopes.map((s) => (
            <span
              key={s}
              className={clsx(
                'inline-flex items-center rounded-pill border px-2 py-0.5 text-[9.5px] font-medium uppercase tracking-wide',
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
          <span className="pill pill-green">
            <span className="dot dot-green" />
            {probe!.tool_count} {probe!.tool_count === 1 ? 'tool' : 'tools'}
          </span>
        ) : probe && !probe.reachable ? (
          <span className="pill pill-red">
            <span className="dot dot-red" />
            Unreachable
          </span>
        ) : (
          <span className="text-[10.5px] uppercase tracking-wide text-sentinel-text-tertiary">
            Not probed
          </span>
        )}
      </div>
    </div>
  );
}

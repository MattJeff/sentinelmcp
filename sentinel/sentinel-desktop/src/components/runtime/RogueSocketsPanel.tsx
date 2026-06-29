// RogueSocketsPanel — "NeighborJack" (F2).
//
// Lists the listening sockets observed on the host that no client config
// declares. A server bound to all interfaces but absent from the inventory is
// a lateral-movement foothold: any neighbour on the LAN can talk to it. The
// observed-sockets table below is passive context for triage.

import { useMemo } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import { Loader2, Radio, ShieldCheck } from 'lucide-react';

import { api } from '@/api/tauri';
import { COMMANDS, type RogueSocketReport } from '@/api/contract';
import SeverityBadge, { severityRank } from './SeverityBadge';

export default function RogueSocketsPanel() {
  const { data, isLoading, error } = useSWR<RogueSocketReport>(
    COMMANDS.listRogueSockets,
    api.listRogueSockets,
    { revalidateOnFocus: false },
  );

  const findings = useMemo(
    () =>
      [...(data?.findings ?? [])].sort(
        (a, b) => severityRank(b.severity) - severityRank(a.severity),
      ),
    [data?.findings],
  );
  const sockets = data?.sockets ?? [];

  return (
    <section className="card flex flex-col gap-6" aria-label="Rogue sockets">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-sentinel-border bg-sentinel-inset">
            <Radio className="h-4.5 w-4.5 text-sentinel-text-secondary" aria-hidden />
          </div>
          <div className="min-w-0">
            <h3 className="text-title text-sentinel-text-primary">
              Rogue sockets
              <span className="ml-2 text-sentinel-text-tertiary normal-case">
                (NeighborJack)
              </span>
            </h3>
            <p className="mt-1 max-w-prose text-caption text-sentinel-text-secondary">
              A server is listening that no client config declares — exposed to
              the LAN, it is a foothold for lateral movement.
            </p>
          </div>
        </div>
        {data && (
          <span className="badge badge-neutral shrink-0">
            <span className="tabular-nums">{data.observed_count}</span>&nbsp;observed ·{' '}
            <span className="tabular-nums">{data.rogue_count}</span>&nbsp;out of inventory
          </span>
        )}
      </div>

      {/* Findings */}
      {error ? (
        <div
          className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg px-4 py-3 text-caption text-sentinel-critical"
          role="alert"
        >
          Failed to scan sockets: {String(error)}
        </div>
      ) : isLoading && !data ? (
        <div className="flex items-center justify-center gap-2 py-8 text-caption text-sentinel-text-secondary">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          Scanning listening sockets…
        </div>
      ) : findings.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-sentinel-border py-10 text-center">
          <ShieldCheck className="h-6 w-6 text-sentinel-ok" aria-hidden />
          <p className="text-body text-sentinel-text-secondary">
            No out-of-inventory sockets
          </p>
          <p className="max-w-prose text-caption text-sentinel-text-tertiary">
            {data && data.observed_count === 0
              ? 'No listening sockets were observed (lsof/ss may be unavailable on this host).'
              : 'Every listening socket maps to a server you already know about.'}
          </p>
        </div>
      ) : (
        <ul className="flex flex-col gap-2">
          {findings.map((f) => (
            <li
              key={f.server_id}
              className="rounded-lg border border-sentinel-critical-border bg-sentinel-critical-bg p-4"
            >
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <span className="text-body font-medium text-sentinel-text-primary">
                  {f.title}
                </span>
              </div>
              <p className="mt-2 max-w-prose text-caption text-sentinel-text-secondary">
                {f.detail}
              </p>
              {f.compliance_refs.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {f.compliance_refs.map((ref) => (
                    <span
                      key={ref}
                      className="badge badge-neutral !px-1.5 !py-0 !text-[10px] !tracking-normal normal-case"
                    >
                      {ref}
                    </span>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}

      {/* Observed sockets — passive context for triage. */}
      {sockets.length > 0 && (
        <div className="flex flex-col gap-2">
          <div className="section-heading">Observed listening sockets</div>
          <div className="overflow-x-auto -mx-2">
            <table className="w-full text-body border-separate border-spacing-y-2 px-2">
              <thead>
                <tr>
                  <th className="section-heading px-3 pb-1 text-left">Proto</th>
                  <th className="section-heading px-3 pb-1 text-left">Address</th>
                  <th className="section-heading px-3 pb-1 text-right">Port</th>
                  <th className="section-heading px-3 pb-1 text-left">Process</th>
                  <th className="section-heading px-3 pb-1 text-left">Exposure</th>
                </tr>
              </thead>
              <tbody>
                {sockets.map((s, i) => (
                  <tr
                    key={`${s.protocol}-${s.address}-${s.port}-${i}`}
                    className={clsx(
                      'transition-colors duration-150',
                      s.bind_all_interfaces
                        ? 'bg-sentinel-critical-bg'
                        : 'bg-sentinel-inset hover:bg-sentinel-raised',
                    )}
                  >
                    <td className="rounded-l-lg px-3 py-2.5 font-mono text-caption text-sentinel-text-tertiary">
                      {s.protocol}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-caption text-sentinel-text-secondary">
                      {s.address}
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono text-caption tabular-nums text-sentinel-text-secondary">
                      {s.port}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-caption text-sentinel-text-tertiary">
                      {s.process ?? '—'}
                      {s.pid != null && (
                        <span className="text-sentinel-text-faint"> (pid {s.pid})</span>
                      )}
                    </td>
                    <td className="rounded-r-lg px-3 py-2.5">
                      {s.bind_all_interfaces ? (
                        <span className="badge badge-high">All interfaces</span>
                      ) : (
                        <span className="badge badge-ok">Loopback</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

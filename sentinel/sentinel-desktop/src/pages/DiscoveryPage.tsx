// Discovery — surface every AI client installed on this Mac and the MCP
// servers it declares. Gated by an explicit authorization dialog so we
// never read the user's config files without consent.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import { Loader2, Telescope } from 'lucide-react';

import { api, onLiveTick } from '@/api/tauri';
import { COMMANDS, type DiscoveredClient, type DiscoveryReport } from '@/api/contract';
import { useDiscoveryAuth } from '@/hooks/useDiscoveryAuth';
import { useToast } from '@/hooks/useToast';
import AuthorizationGate from '@/components/discovery/AuthorizationGate';
import ClientCard from '@/components/discovery/ClientCard';
import LookalikePanel from '@/components/discovery/LookalikePanel';
import SkillsPanel from '@/components/discovery/SkillsPanel';
import ThreatPanel from '@/components/discovery/ThreatPanel';

/**
 * Sort order:
 *  1. installed clients with declared MCP servers (most servers first)
 *  2. installed clients without servers
 *  3. known-but-not-installed (rendered with opacity 50)
 */
function sortClients(a: DiscoveredClient, b: DiscoveredClient): number {
  const aRank = !a.installed ? 2 : a.servers.length > 0 ? 0 : 1;
  const bRank = !b.installed ? 2 : b.servers.length > 0 ? 0 : 1;
  if (aRank !== bRank) return aRank - bRank;
  if (aRank === 0) return b.servers.length - a.servers.length;
  return a.label.localeCompare(b.label);
}

/** Format an ISO timestamp as HH:MM for the "Last scan" indicator. */
function formatLastScan(iso: string | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export default function DiscoveryPage() {
  const { authorized } = useDiscoveryAuth();
  const { addDiscoveryToast } = useToast();
  const [cancelled, setCancelled] = useState(false);
  const [flash, setFlash] = useState(false);
  const flashTimer = useRef<number | null>(null);
  const lastSeenReport = useRef<DiscoveryReport | null>(null);

  const { data, isValidating, mutate } = useSWR(
    authorized ? COMMANDS.discoverSystem : null,
    api.discoverSystem,
    { revalidateOnFocus: false, revalidateOnReconnect: false },
  );

  const clients = useMemo(
    () => [...(data?.clients ?? [])].sort(sortClients),
    [data?.clients],
  );

  const handleScan = useCallback(() => {
    void mutate();
  }, [mutate]);

  // Live background loop: refresh the client list whenever the watcher or
  // periodic sweep fires (e.g. user just ran `claude mcp add`).
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const off = await onLiveTick(() => {
        if (!authorized) return;
        void mutate();
      });
      if (cancelled) off();
      else unlisten = off;
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [authorized, mutate]);

  // Flash the hero panel for 1.5s whenever a fresh report lands, and push
  // a "Scan complete" toast so the user sees an explicit confirmation.
  useEffect(() => {
    if (!data || data === lastSeenReport.current) return;
    lastSeenReport.current = data;
    setFlash(true);
    if (flashTimer.current) window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(false), 1500);
    const clientTotal = data.clients?.length ?? 0;
    const serverTotal = (data.clients ?? []).reduce(
      (acc, c) => acc + c.servers.length,
      0,
    );
    addDiscoveryToast(clientTotal, serverTotal);
    return () => {
      if (flashTimer.current) window.clearTimeout(flashTimer.current);
    };
  }, [data, addDiscoveryToast]);

  const totalClients = clients.length;
  const totalServers = clients.reduce((acc, c) => acc + c.servers.length, 0);
  const lastScan = formatLastScan(
    (data as (DiscoveryReport & { started_at?: string }) | undefined)?.started_at,
  );

  return (
    <div className="relative mx-auto w-full max-w-[1400px] space-y-8">
      {/* Hero */}
      <section
        className={clsx(
          'card flex flex-col gap-6 md:flex-row md:items-center md:justify-between',
          flash && 'animate-pulse-glow',
        )}
        aria-label="Discovery overview"
      >
        <div className="flex min-w-0 items-start gap-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-sentinel-border bg-sentinel-accent-dim">
            <Telescope className="h-5 w-5 text-sentinel-accent" aria-hidden />
          </div>
          <div className="min-w-0">
            <h2 className="text-title text-sentinel-text-primary">
              Discover every MCP server your Mac can reach
            </h2>
            <p className="mt-1 max-w-prose text-body text-sentinel-text-secondary">
              Sentinel reads the config of each known AI client locally and lists
              the MCP servers they declare. Nothing leaves your Mac.
            </p>
            {data && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className="badge badge-neutral">
                  <span className="dot dot-accent" />
                  <strong className="font-semibold tabular-nums">{totalClients}</strong>
                  &nbsp;clients · <strong className="font-semibold tabular-nums">{totalServers}</strong>
                  &nbsp;servers
                </span>
                {lastScan && (
                  <span className="text-caption text-sentinel-text-tertiary tabular-nums">
                    Last scan: {lastScan}
                  </span>
                )}
              </div>
            )}
          </div>
        </div>
        <div className="flex w-full shrink-0 flex-col items-stretch gap-2 sm:flex-row sm:items-center md:w-auto">
          <button
            type="button"
            className="btn btn-primary w-full justify-center sm:w-auto"
            onClick={handleScan}
            disabled={!authorized || isValidating}
          >
            {isValidating ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Telescope className="h-4 w-4" aria-hidden />
            )}
            {isValidating ? 'Scanning…' : 'Scan now'}
          </button>
        </div>
      </section>

      {/* Body */}
      {!authorized ? (
        <div className="card py-12 text-center">
          <div className="section-heading mb-2">Authorization required</div>
          <p className="mx-auto max-w-prose text-body text-sentinel-text-secondary">
            Allow Sentinel to read AI-client configuration files to surface their
            MCP servers. Nothing leaves your Mac.
          </p>
        </div>
      ) : !data ? (
        isValidating ? (
          <DiscoverySkeleton />
        ) : (
          <div className="card py-12 text-center">
            <p className="text-body text-sentinel-text-secondary">
              Click <span className="font-semibold text-sentinel-text-primary">Scan now</span> to start.
            </p>
          </div>
        )
      ) : clients.length === 0 ? (
        <div className="card py-12 text-center">
          <p className="text-body text-sentinel-text-secondary">
            No AI clients detected. Click{' '}
            <span className="font-semibold text-sentinel-text-primary">Scan now</span>.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {clients.map((c) => (
            <ClientCard key={c.kind} client={c} probes={data.probes ?? []} />
          ))}
        </div>
      )}

      {authorized && (
        <>
          <section className="space-y-4" aria-labelledby="discovery-skill-security">
            <h3 id="discovery-skill-security" className="section-heading">
              Skill security
            </h3>
            <SkillsPanel />
          </section>
          <section className="space-y-4" aria-labelledby="discovery-threat-intel">
            <h3 id="discovery-threat-intel" className="section-heading">
              Threat intel
            </h3>
            <ThreatPanel />
          </section>
          <section className="space-y-4" aria-labelledby="discovery-lookalike-scan">
            <h3 id="discovery-lookalike-scan" className="section-heading">
              Lookalike scan
            </h3>
            <LookalikePanel />
          </section>
        </>
      )}

      <AuthorizationGate
        open={!authorized && !cancelled}
        onCancel={() => setCancelled(true)}
      />
    </div>
  );
}

function DiscoverySkeleton() {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3" aria-hidden>
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="card flex flex-col gap-3">
          <div className="skeleton h-5 w-1/2" />
          <div className="skeleton h-3 w-3/4" />
          <div className="skeleton h-3 w-2/3" />
          <div className="skeleton h-7 w-24" />
        </div>
      ))}
    </div>
  );
}

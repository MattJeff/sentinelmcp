// Live Scan page — the "wow" moment. Drives ScanRunner + LiveLog and
// subscribes to scan-progress events from the backend (or a browser-mock loop
// when running outside of Tauri).
import { useCallback, useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import useSWR from 'swr';
import type { UnlistenFn } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';

import ScanRunner, { type ScanMode } from '@/components/ScanRunner';
import LiveLog, { type LogEntry } from '@/components/LiveLog';
import { api, onScanProgress } from '@/api/tauri';
import { COMMANDS, type ScanProgress } from '@/api/contract';

// ─── Proxy capture (mode B) status ───────────────────────────────────────

interface ProxyStatus {
  running: boolean;
  port: number | null;
  upstream: string | null;
  events_seen: number;
}

async function fetchProxyStatus(): Promise<ProxyStatus> {
  try {
    return await invoke<ProxyStatus>(COMMANDS.proxyStatus);
  } catch {
    return { running: false, port: null, upstream: null, events_seen: 0 };
  }
}

async function stopProxyCmd(): Promise<void> {
  // Le nom de la commande doit venir du contrat : le backend expose
  // `stop_proxy` (et non `proxy_stop`), sinon l'invoke échoue à l'exécution.
  await invoke(COMMANDS.stopProxy);
}

type Status = 'idle' | 'running' | 'finished' | 'error';

const INITIAL_PROGRESS: ScanProgress = {
  stage: 'idle',
  servers_discovered: 0,
  tools_discovered: 0,
  time_to_first_red_ms: null,
};

const hasTauri = () =>
  typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !==
  'undefined';

export default function ScanPage() {
  const [mode, setMode] = useState<ScanMode>('stdio');
  const [httpUrl, setHttpUrl] = useState<string>('https://localhost:8765/mcp');
  const [status, setStatus] = useState<Status>('idle');
  const [progress, setProgress] = useState<ScanProgress>(INITIAL_PROGRESS);
  const [entries, setEntries] = useState<LogEntry[]>([]);

  // Browser-mock simulation handle.
  const mockTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mockStartRef = useRef<number>(0);

  const pushLog = useCallback((message: string) => {
    setEntries((prev) => {
      const next = [...prev, { ts: Date.now(), message }];
      // Cap retained lines so the DOM stays light during long runs.
      return next.length > 500 ? next.slice(next.length - 500) : next;
    });
  }, []);

  const applyProgress = useCallback(
    (p: ScanProgress) => {
      setProgress((prev) => ({
        stage: p.stage,
        servers_discovered: Math.max(prev.servers_discovered, p.servers_discovered),
        tools_discovered: Math.max(prev.tools_discovered, p.tools_discovered),
        time_to_first_red_ms:
          p.time_to_first_red_ms ?? prev.time_to_first_red_ms ?? null,
      }));
      if (p.log_line) pushLog(p.log_line);
      if (p.stage === 'finished') setStatus('finished');
      if (p.stage === 'error') setStatus('error');
    },
    [pushLog],
  );

  // Subscribe once on mount.
  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    onScanProgress((p) => applyProgress(p)).then((fn) => {
      if (cancelled) {
        fn();
        return;
      }
      unlisten = fn;
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [applyProgress]);

  const stopMock = useCallback(() => {
    if (mockTimerRef.current) {
      clearInterval(mockTimerRef.current);
      mockTimerRef.current = null;
    }
  }, []);

  const startMock = useCallback(
    (selectedMode: ScanMode) => {
      stopMock();
      mockStartRef.current = Date.now();

      const baseLines: string[] = [
        `mode=${selectedMode} — initializing capture`,
        'opening MCP transport channel',
        'handshake complete — listing servers',
        'discovered server filesystem-server (stdio)',
        'discovered server http://127.0.0.1:8080/mcp',
        'enumerating tools on filesystem-server',
        'tool read_file registered',
        'tool write_file registered',
        'enumerating tools on remote endpoint',
        'tool list_secrets — heuristic flagged',
        'rug-pull detector: comparing fingerprints',
        'fingerprint drift detected on http endpoint',
        'finalizing scan report',
      ];

      let step = 0;
      // Emit a synthetic ScanProgress on each tick.
      mockTimerRef.current = setInterval(() => {
        const now = Date.now();
        const elapsed = now - mockStartRef.current;
        const line = baseLines[step] ?? `tick ${step}`;
        const stage: ScanProgress['stage'] =
          step < 4 ? 'capturing' : step < baseLines.length - 1 ? 'detecting' : 'finished';

        const servers = Math.min(2, Math.floor((step + 1) / 3));
        const tools = Math.min(5, Math.max(0, step - 3));
        const firstRed = step >= 9 ? elapsed : null;

        applyProgress({
          stage,
          servers_discovered: servers,
          tools_discovered: tools,
          time_to_first_red_ms: firstRed,
          log_line: line,
        });

        step += 1;
        if (stage === 'finished') {
          stopMock();
        }
      }, 420);
    },
    [applyProgress, stopMock],
  );

  const handleStart = useCallback(async () => {
    setStatus('running');
    setProgress(INITIAL_PROGRESS);
    setEntries([]);
    pushLog(`Starting scan in ${mode} mode…`);
    if (mode === 'http') {
      pushLog(`HTTP endpoint: ${httpUrl}`);
    }

    try {
      const startParams =
        mode === 'http' ? { mode, httpUrl } : { mode };
      await api.startScan(startParams as Parameters<typeof api.startScan>[0]);
    } catch (err) {
      pushLog(`startScan failed: ${(err as Error).message ?? String(err)}`);
      setStatus('error');
      return;
    }

    if (!hasTauri()) {
      startMock(mode);
    }
  }, [mode, httpUrl, pushLog, startMock]);

  const handleStop = useCallback(async () => {
    stopMock();
    try {
      await api.stopScan();
    } catch (err) {
      pushLog(`stopScan failed: ${(err as Error).message ?? String(err)}`);
    }
    pushLog('Scan stopped by operator.');
    setStatus((s) => (s === 'running' ? 'finished' : s));
    setProgress((p) => ({ ...p, stage: p.stage === 'idle' ? 'idle' : 'finished' }));
  }, [pushLog, stopMock]);

  // Clean up the mock timer on unmount.
  useEffect(() => () => stopMock(), [stopMock]);

  const running = status === 'running';

  return (
    <div className="relative mx-auto w-full max-w-[1400px] flex flex-col gap-6">
      <ProxyBanner />

      <ScanRunner
        mode={mode}
        onModeChange={setMode}
        running={running}
        onStart={handleStart}
        onStop={handleStop}
        progress={progress}
        httpUrl={httpUrl}
        onHttpUrlChange={setHttpUrl}
      />

      <LiveLog entries={entries} />

      <StatusPill status={status} />
    </div>
  );
}

function ProxyBanner() {
  const { data, mutate } = useSWR<ProxyStatus>(
    'proxy_status',
    () => fetchProxyStatus(),
    { refreshInterval: 3000, revalidateOnFocus: false },
  );
  const [stopping, setStopping] = useState(false);

  if (!data?.running) return null;

  const handleStop = async () => {
    if (stopping) return;
    setStopping(true);
    try {
      await stopProxyCmd();
      await mutate();
    } catch {
      // Surface stays silent; Settings page exposes the error path.
    } finally {
      setStopping(false);
    }
  };

  return (
    <div className="surface flex items-center justify-between gap-3 rounded-lg px-4 py-3">
      <span className="badge badge-ok">
        <span className="dot dot-ok" />
        Proxy capture · :{data.port ?? '—'} active
      </span>
      <button
        type="button"
        className="rounded-lg px-2 py-1 text-caption font-medium text-sentinel-accent transition-colors duration-150 hover:underline focus-visible:outline-none focus-visible:shadow-focus disabled:opacity-40"
        onClick={handleStop}
        disabled={stopping}
      >
        {stopping ? 'Stopping…' : 'Stop'}
      </button>
    </div>
  );
}

interface StatusPillProps {
  status: Status;
}

function StatusPill({ status }: StatusPillProps) {
  const label =
    status === 'idle'
      ? 'Idle'
      : status === 'running'
        ? 'Running'
        : status === 'finished'
          ? 'Finished'
          : 'Error';

  const badgeClass =
    status === 'running'
      ? 'badge-accent'
      : status === 'finished'
        ? 'badge-ok'
        : status === 'error'
          ? 'badge-critical'
          : 'badge-neutral';

  const dotClass =
    status === 'running'
      ? 'dot-accent'
      : status === 'finished'
        ? 'dot-ok'
        : status === 'error'
          ? 'dot-critical'
          : 'dot-info';

  return (
    <div className="pointer-events-none sticky bottom-4 z-10 flex justify-end">
      <span
        role="status"
        aria-live="polite"
        className={clsx('badge pointer-events-auto shadow-raised', badgeClass)}
      >
        <span
          className={clsx(
            'dot',
            dotClass,
            (status === 'running' || status === 'error') && 'animate-pulse',
          )}
        />
        {label}
      </span>
    </div>
  );
}

// Glass-card scan controller. Owns the mode selector, the start/stop button,
// the KPI tiles and the progress bar. Pure presentation — state lives in the
// parent ScanPage.
import clsx from 'clsx';
import { Play, Square, Server, Wrench, Timer } from 'lucide-react';
import type { ScanProgress } from '@/api/contract';

export type ScanMode = 'stdio' | 'http';

interface ScanRunnerProps {
  mode: ScanMode;
  onModeChange: (m: ScanMode) => void;
  running: boolean;
  onStart: () => void;
  onStop: () => void;
  progress: ScanProgress;
  httpUrl: string;
  onHttpUrlChange: (url: string) => void;
}

const MODES: { id: ScanMode; label: string; hint: string }[] = [
  { id: 'stdio', label: 'Stdio', hint: 'Probe declared MCP servers locally' },
  {
    id: 'http',
    label: 'HTTP',
    hint: 'Hit a remote Streamable HTTP MCP endpoint and probe its tools/list.',
  },
];

function isValidHttpUrl(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function stageRatio(stage: ScanProgress['stage']): number {
  switch (stage) {
    case 'idle':
      return 0;
    case 'capturing':
      return 0.35;
    case 'detecting':
      return 0.75;
    case 'finished':
      return 1;
    case 'error':
      return 1;
  }
}

export default function ScanRunner({
  mode,
  onModeChange,
  running,
  onStart,
  onStop,
  progress,
  httpUrl,
  onHttpUrlChange,
}: ScanRunnerProps) {
  const ratio = stageRatio(progress.stage);
  const pct = Math.max(0, Math.min(1, ratio)) * 100;
  const httpUrlValid = isValidHttpUrl(httpUrl);
  const httpUrlInvalid = mode === 'http' && httpUrl.trim().length > 0 && !httpUrlValid;
  const startDisabled = mode === 'http' && !httpUrlValid;

  return (
    <section className="card animate-fade-up">
      {/* Mode selector + action */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="section-heading mb-2">Scan mode</div>
          <div className="glass-soft inline-flex rounded-pill p-1">
            {MODES.map((m) => {
              const isActive = mode === m.id;
              return (
                <button
                  key={m.id}
                  type="button"
                  disabled={running}
                  onClick={() => onModeChange(m.id)}
                  className={clsx(
                    'px-4 py-1.5 text-[13px] font-medium rounded-pill transition-all duration-150',
                    isActive
                      ? 'bg-white/15 text-white shadow-glass-soft'
                      : 'text-sentinel-text-secondary hover:text-white',
                    running && !isActive && 'opacity-40 cursor-not-allowed',
                  )}
                  title={m.hint}
                >
                  {m.label}
                </button>
              );
            })}
          </div>
          <div className="mt-2 text-[11px] text-sentinel-text-tertiary">
            {MODES.find((m) => m.id === mode)?.hint}
          </div>
        </div>

        <button
          type="button"
          onClick={running ? onStop : onStart}
          disabled={!running && startDisabled}
          className={clsx(
            'btn',
            running ? 'btn-danger' : 'btn-primary',
            'px-5 py-2.5 text-[13px] min-h-[44px] w-full md:w-auto justify-center',
            !running && startDisabled && 'opacity-50 cursor-not-allowed',
          )}
        >
          {running ? (
            <>
              <Square className="h-4 w-4" />
              Stop scan
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Start scan
            </>
          )}
        </button>
      </div>

      {mode === 'http' && (
        <div className="mt-4">
          <label
            htmlFor="scan-http-endpoint"
            className="section-heading mb-1.5 block"
          >
            HTTP endpoint
          </label>
          <input
            id="scan-http-endpoint"
            type="url"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            disabled={running}
            value={httpUrl}
            onChange={(e) => onHttpUrlChange(e.target.value)}
            placeholder="https://localhost:8765/mcp"
            aria-invalid={httpUrlInvalid}
            className={clsx(
              'glass-soft w-full rounded-glass px-3 py-2 text-[13px] text-white placeholder:text-sentinel-text-tertiary outline-none transition-colors',
              httpUrlInvalid
                ? 'ring-1 ring-sentinel-red/60 focus:ring-sentinel-red'
                : 'focus:ring-1 focus:ring-sentinel-blue-glow',
              running && 'opacity-60 cursor-not-allowed',
            )}
          />
          <div className="mt-1 text-[11px] text-sentinel-text-tertiary">
            {httpUrlInvalid
              ? 'Enter a valid http(s) URL, e.g. https://localhost:8765/mcp'
              : 'Streamable HTTP MCP endpoint that exposes a tools/list method.'}
          </div>
        </div>
      )}

      {/* KPI tiles */}
      <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Kpi
          icon={<Server className="h-4 w-4 text-sentinel-blue-glow" />}
          label="Servers found"
          value={String(progress.servers_discovered)}
        />
        <Kpi
          icon={<Wrench className="h-4 w-4 text-sentinel-blue-glow" />}
          label="Tools found"
          value={String(progress.tools_discovered)}
        />
        <Kpi
          icon={<Timer className="h-4 w-4 text-sentinel-red-glow" />}
          label="Time to first red"
          value={
            progress.time_to_first_red_ms == null
              ? '—'
              : `${progress.time_to_first_red_ms} ms`
          }
          accent={progress.time_to_first_red_ms != null}
        />
      </div>

      {/* Progress bar */}
      <div className="mt-5">
        <div className="flex items-center justify-between mb-1.5">
          <span className="section-heading">Progress</span>
          <span className="text-[11px] text-sentinel-text-tertiary capitalize">
            {progress.stage}
          </span>
        </div>
        <div className="h-2 w-full rounded-pill bg-white/5 overflow-hidden">
          <div
            className={clsx(
              'h-full rounded-pill transition-[width] duration-500 ease-out',
              running
                ? 'animate-shimmer bg-[length:200%_100%] bg-gradient-to-r from-sentinel-blue via-sentinel-purple to-sentinel-blue'
                : progress.stage === 'error'
                  ? 'bg-sentinel-red'
                  : progress.stage === 'finished'
                    ? 'bg-sentinel-green'
                    : 'bg-white/20',
            )}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>
    </section>
  );
}

interface KpiProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  accent?: boolean;
}

function Kpi({ icon, label, value, accent }: KpiProps) {
  return (
    <div className="glass-soft rounded-glass p-4">
      <div className="flex items-center gap-2">
        {icon}
        <span className="section-heading">{label}</span>
      </div>
      <div
        className={clsx(
          'mt-2 text-[28px] font-semibold tracking-tight tabular-nums',
          accent ? 'text-sentinel-red-glow' : 'text-sentinel-text-primary',
        )}
      >
        {value}
      </div>
    </div>
  );
}

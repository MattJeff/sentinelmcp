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
      <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="section-heading mb-2">Scan mode</div>
          <div
            role="group"
            aria-label="Scan mode"
            className="inline-flex gap-1 rounded-lg border border-sentinel-border bg-sentinel-inset p-1"
          >
            {MODES.map((m) => {
              const isActive = mode === m.id;
              return (
                <button
                  key={m.id}
                  type="button"
                  disabled={running}
                  aria-pressed={isActive}
                  onClick={() => onModeChange(m.id)}
                  className={clsx(
                    'rounded-lg px-4 py-1.5 text-body font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:shadow-focus',
                    isActive
                      ? 'bg-sentinel-raised text-sentinel-text-primary shadow-surface'
                      : 'text-sentinel-text-secondary hover:text-sentinel-text-primary',
                    running && !isActive && 'opacity-40 cursor-not-allowed',
                  )}
                  title={m.hint}
                >
                  {m.label}
                </button>
              );
            })}
          </div>
          <div className="mt-2 text-caption text-sentinel-text-tertiary">
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
            'w-full justify-center md:w-auto',
            !running && startDisabled && 'opacity-40 cursor-not-allowed',
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
        <div className="mt-6">
          <label
            htmlFor="scan-http-endpoint"
            className="section-heading mb-2 block"
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
              'input w-full',
              httpUrlInvalid &&
                'border-sentinel-critical-border ring-1 ring-sentinel-critical/40 focus:border-sentinel-critical focus:ring-sentinel-critical/40',
              running && 'opacity-40 cursor-not-allowed',
            )}
          />
          <div
            className={clsx(
              'mt-2 text-caption',
              httpUrlInvalid ? 'text-sentinel-critical' : 'text-sentinel-text-tertiary',
            )}
          >
            {httpUrlInvalid
              ? 'Enter a valid http(s) URL, e.g. https://localhost:8765/mcp'
              : 'Streamable HTTP MCP endpoint that exposes a tools/list method.'}
          </div>
        </div>
      )}

      {/* KPI tiles */}
      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Kpi
          icon={<Server className="h-4 w-4 text-sentinel-accent" />}
          label="Servers found"
          value={String(progress.servers_discovered)}
        />
        <Kpi
          icon={<Wrench className="h-4 w-4 text-sentinel-accent" />}
          label="Tools found"
          value={String(progress.tools_discovered)}
        />
        <Kpi
          icon={<Timer className="h-4 w-4 text-sentinel-critical" />}
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
      <div className="mt-6">
        <div className="flex items-center justify-between mb-2">
          <span className="section-heading">Progress</span>
          <span className="text-caption text-sentinel-text-tertiary capitalize tabular-nums">
            {progress.stage}
          </span>
        </div>
        <div
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(pct)}
          className="h-2 w-full rounded-pill bg-white/6 overflow-hidden"
        >
          <div
            className={clsx(
              'h-full rounded-pill transition-[width] duration-500 ease-out',
              running
                ? 'animate-shimmer bg-[length:200%_100%] bg-gradient-to-r from-sentinel-accent via-sentinel-violet to-sentinel-accent'
                : progress.stage === 'error'
                  ? 'bg-sentinel-critical'
                  : progress.stage === 'finished'
                    ? 'bg-sentinel-ok'
                    : 'bg-white/12',
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
          'mt-2 text-metric-lg tabular-nums',
          accent ? 'text-sentinel-critical' : 'text-sentinel-text-primary',
        )}
      >
        {value}
      </div>
    </div>
  );
}

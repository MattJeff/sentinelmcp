import { ArrowRight, Eye, FileCheck2, Radar, Shield } from 'lucide-react';
import { useOnboarding } from '../hooks/useOnboarding';

interface Step {
  title: string;
  description: string;
  Icon: typeof Shield;
}

const STEPS: Step[] = [
  {
    title: 'Scan',
    description: 'Run a passive capture to discover MCP servers.',
    Icon: Radar,
  },
  {
    title: 'Watch',
    description:
      'Continuous monitoring; fingerprints persist across sessions.',
    Icon: Eye,
  },
  {
    title: 'Prove',
    description: 'Generate a signed bundle for your auditor.',
    Icon: FileCheck2,
  },
];

export default function Welcome() {
  const { done, dismiss } = useOnboarding();

  if (done) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="sentinel-welcome-title"
      className="app-bg fixed inset-0 z-50 flex items-center justify-center overflow-y-auto p-8"
    >
      {/* Overlay scrim behind the panel */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-black/50 backdrop-blur-xs"
      />

      <div className="surface-raised relative w-full max-w-2xl animate-fade-up rounded-xl p-8 shadow-overlay">
        {/* Header — product mark + wordmark */}
        <div className="flex items-center gap-4">
          <div
            className="flex h-12 w-12 items-center justify-center rounded-xl border border-sentinel-border bg-sentinel-accent-dim"
            aria-hidden
          >
            <Shield
              className="h-6 w-6 text-sentinel-accent"
              strokeWidth={2}
            />
          </div>
          <div className="flex flex-col gap-1">
            <span className="section-heading">Sentinel</span>
            <span className="text-title text-sentinel-text-primary">
              Sentinel MCP
            </span>
          </div>
        </div>

        {/* Headline */}
        <div className="mt-8 space-y-3">
          <h1
            id="sentinel-welcome-title"
            className="text-metric-lg text-sentinel-text-primary"
          >
            See every MCP server your agents reach.
          </h1>
          <p className="max-w-xl text-body leading-relaxed text-sentinel-text-secondary">
            Sentinel observes the Model Context Protocol traffic on your Mac,
            fingerprints every server, and flags rug-pulls and prompt-injection
            risks — full OWASP MCP09 and MCP03 coverage, on-device.
          </p>
        </div>

        {/* Steps */}
        <ol className="mt-8 flex flex-col gap-3">
          {STEPS.map((step, idx) => (
            <li
              key={step.title}
              className="glass-soft flex items-start gap-4 rounded-glass p-4"
            >
              <div
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sentinel-accent-dim text-caption font-semibold tabular-nums text-sentinel-accent"
                aria-hidden
              >
                {idx + 1}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <step.Icon
                    className="h-4 w-4 text-sentinel-accent"
                    strokeWidth={2}
                    aria-hidden
                  />
                  <h3 className="text-body font-semibold text-sentinel-text-primary">
                    {step.title}
                  </h3>
                </div>
                <p className="mt-1 text-caption leading-relaxed text-sentinel-text-tertiary">
                  {step.description}
                </p>
              </div>
            </li>
          ))}
        </ol>

        {/* CTA + skip */}
        <div className="mt-8 flex items-center justify-between gap-4">
          <button
            type="button"
            onClick={dismiss}
            className="btn btn-primary no-drag group"
          >
            <span>Get started</span>
            <ArrowRight
              className="h-4 w-4 transition-transform duration-150 group-hover:translate-x-0.5"
              strokeWidth={2}
              aria-hidden
            />
          </button>
          <button
            type="button"
            onClick={dismiss}
            className="no-drag rounded-lg px-2 py-1 text-body font-medium text-sentinel-text-tertiary transition-colors duration-150 hover:text-sentinel-text-secondary focus-visible:outline-none focus-visible:shadow-focus"
          >
            Skip the tour
          </button>
        </div>

        {/* Reassurance */}
        <p className="mt-8 text-center text-caption text-sentinel-text-tertiary">
          Read-only by default
          <span className="mx-2 text-sentinel-text-faint" aria-hidden>
            ·
          </span>
          Nothing leaves your Mac
          <span className="mx-2 text-sentinel-text-faint" aria-hidden>
            ·
          </span>
          OWASP MCP09/MCP03 covered
        </p>
      </div>
    </div>
  );
}

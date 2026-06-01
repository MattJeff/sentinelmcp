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
      {/* Aurora wash to lift the panel off the shell */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-aurora-1 opacity-80"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-aurora-2 opacity-60"
      />

      <div className="glass-strong relative w-full max-w-2xl animate-fade-up rounded-glass p-12">
        {/* Header — gradient icon + wordmark */}
        <div className="flex items-center gap-5">
          <div
            className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-sentinel-blue to-sentinel-purple shadow-glow-blue"
            aria-hidden
          >
            <Shield className="h-9 w-9 text-white" strokeWidth={2.25} />
          </div>
          <div className="flex flex-col">
            <span className="section-heading">Sentinel</span>
            <span className="text-[22px] font-semibold tracking-tight text-sentinel-text-primary">
              Sentinel MCP
            </span>
          </div>
        </div>

        {/* Headline */}
        <div className="mt-10 space-y-3">
          <h1
            id="sentinel-welcome-title"
            className="text-[34px] font-semibold leading-tight tracking-tight text-sentinel-text-primary"
          >
            See every MCP server your agents reach.
          </h1>
          <p className="max-w-xl text-[15px] leading-relaxed text-sentinel-text-secondary">
            Sentinel observes the Model Context Protocol traffic on your Mac,
            fingerprints every server, and flags rug-pulls and prompt-injection
            risks — full OWASP MCP09 and MCP03 coverage, on-device.
          </p>
        </div>

        {/* Steps */}
        <ol className="mt-10 flex flex-col gap-5">
          {STEPS.map((step, idx) => (
            <li
              key={step.title}
              className="flex items-start gap-5 rounded-glass glass-soft p-5"
            >
              <div
                className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-sentinel-blue to-sentinel-purple text-[15px] font-semibold text-white shadow-glow-blue"
                aria-hidden
              >
                {idx + 1}
              </div>
              <div className="flex-1 pt-0.5">
                <div className="flex items-center gap-2">
                  <step.Icon
                    className="h-4 w-4 text-sentinel-blue-glow"
                    strokeWidth={2.25}
                  />
                  <h3 className="text-[15px] font-semibold text-sentinel-text-primary">
                    {step.title}
                  </h3>
                </div>
                <p className="mt-1.5 text-[13px] leading-relaxed text-sentinel-text-tertiary">
                  {step.description}
                </p>
              </div>
            </li>
          ))}
        </ol>

        {/* CTA + skip */}
        <div className="mt-10 flex items-center justify-between gap-4">
          <button
            type="button"
            onClick={dismiss}
            className="btn-primary btn no-drag group"
          >
            <span>Get started</span>
            <ArrowRight
              className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5"
              strokeWidth={2.25}
            />
          </button>
          <button
            type="button"
            onClick={dismiss}
            className="no-drag text-[13px] font-medium text-sentinel-text-tertiary transition-colors duration-150 hover:text-sentinel-text-secondary"
          >
            Skip the tour
          </button>
        </div>

        {/* Reassurance */}
        <p className="mt-8 text-center text-[12px] tracking-wide text-sentinel-text-tertiary">
          Read-only by default
          <span className="mx-2 text-sentinel-text-tertiary/60">·</span>
          Nothing leaves your Mac
          <span className="mx-2 text-sentinel-text-tertiary/60">·</span>
          OWASP MCP09/MCP03 covered
        </p>
      </div>
    </div>
  );
}

// Runtime defenses — the live, in-the-loop protections (Vague D).
//
// Three sections, each consuming the runtime command contract:
//   1. Approve before run — the opt-in gate + the queue of held calls.
//   2. Rogue sockets       — listening sockets observed out of inventory.
//   3. Known CVEs          — supply-chain matches against pinned packages.
//
// The page is intentionally read-mostly: the only mutating actions are the
// gate toggle and per-call approve/deny, all routed through the existing
// toast surface for feedback.

import { ShieldHalf } from 'lucide-react';

import GatePanel from '@/components/runtime/GatePanel';
import RogueSocketsPanel from '@/components/runtime/RogueSocketsPanel';
import CvePanel from '@/components/runtime/CvePanel';

export default function RuntimeDefensePage() {
  return (
    <div className="relative mx-auto w-full max-w-[1400px] space-y-8">
      {/* Hero */}
      <section
        className="card flex items-start gap-4"
        aria-label="Runtime defenses overview"
      >
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-sentinel-border bg-sentinel-accent-dim">
          <ShieldHalf className="h-5 w-5 text-sentinel-accent" aria-hidden />
        </div>
        <div className="min-w-0">
          <h2 className="text-title text-sentinel-text-primary">
            Defend MCP traffic while it runs
          </h2>
          <p className="mt-1 max-w-prose text-body text-sentinel-text-secondary">
            Beyond the static inventory, these are the live protections: hold
            risky calls for approval, catch servers listening out of inventory,
            and flag pinned packages with known CVEs. Everything runs locally.
          </p>
        </div>
      </section>

      {/* 1 — Approve before run */}
      <section className="space-y-4" aria-labelledby="runtime-gate">
        <h3 id="runtime-gate" className="sr-only">
          Approve before run
        </h3>
        <GatePanel />
      </section>

      {/* 2 — Rogue sockets */}
      <section className="space-y-4" aria-labelledby="runtime-sockets">
        <h3 id="runtime-sockets" className="sr-only">
          Rogue sockets
        </h3>
        <RogueSocketsPanel />
      </section>

      {/* 3 — Known CVEs */}
      <section className="space-y-4" aria-labelledby="runtime-cve">
        <h3 id="runtime-cve" className="sr-only">
          Known CVEs
        </h3>
        <CvePanel />
      </section>
    </div>
  );
}

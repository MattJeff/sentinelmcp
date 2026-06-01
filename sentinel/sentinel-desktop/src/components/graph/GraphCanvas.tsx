// GraphCanvas — tiny force-directed SVG renderer for the Trust Graph.
// No external graph dependency: we use linear repulsion + spring attraction,
// damped over time with requestAnimationFrame. ~80 lines of physics.
//
// Built by agent U2.

import { useEffect, useMemo, useRef, useState } from 'react';
import clsx from 'clsx';

export type TrustNodeKind = 'client' | 'server' | 'scope';

export interface TrustNode {
  id: string;
  label: string;
  kind: TrustNodeKind;
  /** 0..1 risk, used to tone scope chips and pulse high-risk clients. */
  risk?: number;
  /** Optional initial blast-radius score (shown on hover for clients). */
  score?: number;
}

export interface TrustEdge {
  source: string;
  target: string;
}

export interface GraphCanvasProps {
  nodes: TrustNode[];
  edges: TrustEdge[];
  selectedId?: string | null;
  pulseId?: string | null;
  onSelect?: (id: string | null) => void;
  width?: number;
  height?: number;
}

interface SimNode extends TrustNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  /** Preferred column x (clients=left, servers=middle, scopes=right). */
  cx: number;
}

const COL_RATIO: Record<TrustNodeKind, number> = {
  client: 0.18,
  server: 0.5,
  scope: 0.82,
};

export default function GraphCanvas({
  nodes,
  edges,
  selectedId,
  pulseId,
  onSelect,
  width = 720,
  height = 520,
}: GraphCanvasProps) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const [, force] = useState(0);
  const [hoverId, setHoverId] = useState<string | null>(null);

  // Build a stable adjacency once.
  const adjacency = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const n of nodes) map.set(n.id, new Set());
    for (const e of edges) {
      map.get(e.source)?.add(e.target);
      map.get(e.target)?.add(e.source);
    }
    return map;
  }, [nodes, edges]);

  // Build/refresh sim nodes when the input set changes.
  const simRef = useRef<SimNode[]>([]);
  useEffect(() => {
    const next: SimNode[] = nodes.map((n, i) => {
      const previous = simRef.current.find((s) => s.id === n.id);
      const cx = width * COL_RATIO[n.kind];
      if (previous) {
        return { ...previous, ...n, cx };
      }
      // Stagger initial y by kind so columns start tidy.
      const kindIdx = nodes.filter((m) => m.kind === n.kind).indexOf(n);
      const total = Math.max(1, nodes.filter((m) => m.kind === n.kind).length);
      const y = ((kindIdx + 1) / (total + 1)) * height;
      return {
        ...n,
        cx,
        x: cx + (Math.random() - 0.5) * 20,
        y: y + (Math.random() - 0.5) * 20,
        vx: 0,
        vy: 0,
      };
    });
    simRef.current = next;
    force((t) => t + 1);
  }, [nodes, width, height]);

  // Tiny physics loop.
  useEffect(() => {
    let alive = true;
    const step = () => {
      if (!alive) return;
      const sim = simRef.current;
      const REPEL = 1800;
      const SPRING = 0.012;
      const SPRING_LEN = 110;
      const COLUMN_PULL = 0.05;
      const DAMP = 0.86;
      const edgeList = edges;

      for (let i = 0; i < sim.length; i++) {
        const a = sim[i];
        // Column pull (keeps clients/servers/scopes in their lanes).
        a.vx += (a.cx - a.x) * COLUMN_PULL;
        // Soft vertical centring.
        a.vy += (height / 2 - a.y) * 0.0015;
        for (let j = i + 1; j < sim.length; j++) {
          const b = sim[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const distSq = dx * dx + dy * dy + 0.01;
          const dist = Math.sqrt(distSq);
          // Linear repulsion (1/dist), capped to avoid explosions.
          const f = Math.min(REPEL / distSq, 8);
          const fx = (dx / dist) * f;
          const fy = (dy / dist) * f;
          a.vx += fx;
          a.vy += fy;
          b.vx -= fx;
          b.vy -= fy;
        }
      }
      // Spring attraction along edges.
      const byId = new Map(sim.map((n) => [n.id, n] as const));
      for (const e of edgeList) {
        const s = byId.get(e.source);
        const t = byId.get(e.target);
        if (!s || !t) continue;
        const dx = t.x - s.x;
        const dy = t.y - s.y;
        const dist = Math.sqrt(dx * dx + dy * dy) + 0.01;
        const stretch = dist - SPRING_LEN;
        const fx = (dx / dist) * stretch * SPRING;
        const fy = (dy / dist) * stretch * SPRING;
        s.vx += fx;
        s.vy += fy;
        t.vx -= fx;
        t.vy -= fy;
      }
      // Integrate + clamp inside the viewport.
      const PAD = 28;
      for (const n of sim) {
        n.vx *= DAMP;
        n.vy *= DAMP;
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < PAD) n.x = PAD;
        if (n.x > width - PAD) n.x = width - PAD;
        if (n.y < PAD) n.y = PAD;
        if (n.y > height - PAD) n.y = height - PAD;
      }
      force((t) => (t + 1) % 1_000_000);
      rafRef.current = requestAnimationFrame(step);
    };
    rafRef.current = requestAnimationFrame(step);
    return () => {
      alive = false;
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
    };
  }, [edges, width, height]);

  // Highlight set: hovered or selected node + its neighbours.
  const focusId = hoverId ?? selectedId ?? null;
  const focusSet = useMemo(() => {
    if (!focusId) return null;
    const s = new Set<string>([focusId]);
    for (const n of adjacency.get(focusId) ?? []) s.add(n);
    return s;
  }, [focusId, adjacency]);

  const sim = simRef.current;
  const byId = new Map(sim.map((n) => [n.id, n] as const));

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${width} ${height}`}
      className="w-full h-full select-none"
      role="img"
      aria-label="Trust graph"
      onMouseLeave={() => setHoverId(null)}
    >
      <defs>
        <radialGradient id="grad-client" cx="35%" cy="30%" r="80%">
          <stop offset="0%" stopColor="#5e9eff" />
          <stop offset="100%" stopColor="#0a84ff" />
        </radialGradient>
        <radialGradient id="grad-server" cx="35%" cy="30%" r="80%">
          <stop offset="0%" stopColor="#d39bff" />
          <stop offset="100%" stopColor="#bf5af2" />
        </radialGradient>
        <radialGradient id="grad-scope-green" cx="35%" cy="30%" r="80%">
          <stop offset="0%" stopColor="#7fe48b" />
          <stop offset="100%" stopColor="#34c759" />
        </radialGradient>
        <radialGradient id="grad-scope-orange" cx="35%" cy="30%" r="80%">
          <stop offset="0%" stopColor="#ffd28a" />
          <stop offset="100%" stopColor="#ff9f0a" />
        </radialGradient>
        <radialGradient id="grad-scope-red" cx="35%" cy="30%" r="80%">
          <stop offset="0%" stopColor="#ff8a82" />
          <stop offset="100%" stopColor="#ff453a" />
        </radialGradient>
      </defs>

      {/* Column hints (very subtle frosted lanes). */}
      {(['client', 'server', 'scope'] as TrustNodeKind[]).map((k) => (
        <line
          key={k}
          x1={width * COL_RATIO[k]}
          x2={width * COL_RATIO[k]}
          y1={16}
          y2={height - 16}
          stroke="rgba(255,255,255,0.04)"
          strokeWidth={1}
        />
      ))}

      {/* Edges. */}
      <g>
        {edges.map((e, i) => {
          const a = byId.get(e.source);
          const b = byId.get(e.target);
          if (!a || !b) return null;
          const isFocus =
            !focusSet ||
            (focusSet.has(a.id) && focusSet.has(b.id));
          return (
            <line
              key={`e-${i}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={isFocus ? 'rgba(255,255,255,0.55)' : 'rgba(255,255,255,0.08)'}
              strokeWidth={isFocus ? 1.4 : 1}
              style={{ transition: 'stroke 180ms ease, stroke-width 180ms ease' }}
            />
          );
        })}
      </g>

      {/* Nodes. */}
      <g>
        {sim.map((n) => {
          const dim = focusSet ? !focusSet.has(n.id) : false;
          const fill = nodeFill(n);
          const isPulse = pulseId === n.id;
          const isSelected = selectedId === n.id;
          return (
            <g
              key={n.id}
              transform={`translate(${n.x}, ${n.y})`}
              style={{
                cursor: 'pointer',
                opacity: dim ? 0.28 : 1,
                transition: 'opacity 180ms ease',
              }}
              onMouseEnter={() => setHoverId(n.id)}
              onMouseLeave={() => setHoverId((cur) => (cur === n.id ? null : cur))}
              onClick={() => onSelect?.(n.id === selectedId ? null : n.id)}
            >
              {/* Halo. */}
              <circle
                r={isSelected ? 18 : 14}
                fill={fill}
                opacity={0.18}
                className={clsx(isPulse && 'animate-pulse-glow')}
              />
              <circle
                r={12}
                fill={fill}
                stroke="rgba(255,255,255,0.35)"
                strokeWidth={isSelected ? 1.6 : 0.8}
              />
              <text
                x={n.kind === 'scope' ? 18 : n.kind === 'client' ? -18 : 18}
                y={4}
                textAnchor={n.kind === 'client' ? 'end' : 'start'}
                fontSize={11}
                fill={dim ? 'rgba(245,247,251,0.45)' : 'rgba(245,247,251,0.92)'}
                style={{ pointerEvents: 'none' }}
              >
                {n.label}
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}

function nodeFill(n: TrustNode): string {
  if (n.kind === 'client') return 'url(#grad-client)';
  if (n.kind === 'server') return 'url(#grad-server)';
  // scope — color by risk.
  const r = n.risk ?? 0;
  if (r >= 0.66) return 'url(#grad-scope-red)';
  if (r >= 0.33) return 'url(#grad-scope-orange)';
  return 'url(#grad-scope-green)';
}

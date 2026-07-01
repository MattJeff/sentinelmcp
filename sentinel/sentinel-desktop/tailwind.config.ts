import type { Config } from 'tailwindcss';

// ─────────────────────────────────────────────────────────────────────────────
// Sentinel MCP — design system « Console calme » (enterprise security).
//
// Direction : fonds mats froids, bordures hairline, rayons contenus, accents
// réservés à la sémantique de sévérité. La couleur ne décore pas : elle signale.
//
// Échelle d'espacement (Tailwind natif, pas de token custom) :
//   4  → p-1 / gap-1   : micro (icône+label dans une pill)
//   8  → p-2 / gap-2   : intra-composant
//   12 → p-3 / gap-3   : rows de listes/tables denses
//   16 → p-4 / gap-4   : cartes compactes, gouttières de grilles
//   24 → p-6 / gap-6   : cartes standard (.card), entre sections proches
//   32 → p-8 / gap-8   : gouttières de page, entre grandes sections
//
// Sévérités (uniques accents sémantiques) :
//   info → sentinel-info | medium → sentinel-medium | high → sentinel-high
//   critical → sentinel-critical | sain/ok → sentinel-ok
//   Chaque niveau expose fg (`sentinel-<sev>`), `-bg` et `-border`.
// ─────────────────────────────────────────────────────────────────────────────

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx,js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          // ── Fonds — neutres froids, opaques (plus de glassmorphism) ──
          deep: '#0a0b10', // canvas app / body
          ink: '#0e0f16', // fond de page
          surface: '#14151d', // cartes, panneaux
          mid: '#14151d', // alias back-compat de surface
          raised: '#1b1c27', // popovers, drawers, rows hover
          inset: 'rgba(255,255,255,0.03)', // zones encastrées (inputs, code)

          // ── Bordures hairline ──
          border: 'rgba(255,255,255,0.08)',
          'border-soft': 'rgba(255,255,255,0.05)',
          'border-strong': 'rgba(255,255,255,0.14)',

          // ── Texte — 4 crans ──
          'text-primary': '#e8ebf1',
          'text-secondary': 'rgba(232,235,241,0.65)',
          'text-tertiary': 'rgba(232,235,241,0.45)',
          'text-faint': 'rgba(232,235,241,0.28)',

          // ── Accent produit unique (focus, liens, sélection, primary) ──
          accent: '#6E56F7',
          'accent-dim': 'rgba(110,86,247,0.14)',

          // ── Sévérités — fg / bg / border ──
          info: '#8ea3c0',
          'info-bg': 'rgba(142,163,192,0.10)',
          'info-border': 'rgba(142,163,192,0.28)',
          medium: '#d9a83c',
          'medium-bg': 'rgba(217,168,60,0.10)',
          'medium-border': 'rgba(217,168,60,0.30)',
          high: '#e8804f',
          'high-bg': 'rgba(232,128,79,0.10)',
          'high-border': 'rgba(232,128,79,0.30)',
          critical: '#e5534b',
          'critical-bg': 'rgba(229,83,75,0.12)',
          'critical-border': 'rgba(229,83,75,0.34)',
          ok: '#4cc38a',
          'ok-bg': 'rgba(76,195,138,0.10)',
          'ok-border': 'rgba(76,195,138,0.28)',

          // ── Alias back-compat (composants existants) — retunés calmes ──
          green: '#4cc38a',
          'green-glow': '#3da876',
          amber: '#d9a83c',
          'amber-glow': '#c2912e',
          orange: '#e8804f',
          'orange-glow': '#d06a3b',
          coral: '#e8804f',
          'coral-glow': '#d06a3b',
          red: '#e5534b',
          'red-glow': '#d24840',
          cyan: '#6E56F7',
          'cyan-glow': '#5b46e0',
          violet: '#9b8bff',
          'violet-glow': '#7c6af0',
          blue: '#6E56F7',
          'blue-glow': '#5b46e0',
          purple: '#9b8bff',
          'purple-glow': '#7c6af0',
          glass: 'rgba(255,255,255,0.04)',
          'glass-strong': '#14151d',
          'glass-border': 'rgba(255,255,255,0.08)',
          'glass-line': 'rgba(255,255,255,0.05)',
        },
      },
      // Pas d'arc-en-ciel d'alphas arbitraires : crans intermédiaires officiels
      // pour les modificateurs (`bg-white/6`, `border-white/8`, …).
      opacity: {
        '3': '0.03',
        '4': '0.04',
        '6': '0.06',
        '8': '0.08',
        '12': '0.12',
        '14': '0.14',
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          'SF Pro Display',
          'SF Pro Text',
          'Inter',
          'system-ui',
          'sans-serif',
        ],
        mono: ['SF Mono', 'JetBrains Mono', 'Menlo', 'monospace'],
      },
      fontSize: {
        // Hiérarchie typographique projet — utiliser ces crans, pas du sur-mesure.
        'metric-lg': ['28px', { lineHeight: '32px', letterSpacing: '-0.02em', fontWeight: '600' }],
        metric: ['20px', { lineHeight: '24px', letterSpacing: '-0.01em', fontWeight: '600' }],
        title: ['15px', { lineHeight: '20px', letterSpacing: '-0.01em', fontWeight: '600' }],
        body: ['13px', { lineHeight: '20px' }],
        caption: ['12px', { lineHeight: '16px' }],
        overline: ['11px', { lineHeight: '16px', letterSpacing: '0.08em', fontWeight: '500' }],
      },
      backdropBlur: {
        xs: '4px',
        glass: '12px',
        'glass-strong': '24px', // réservé aux overlays/modals
      },
      boxShadow: {
        // Élévation : la carte au repos = hairline, pas d'ombre portée.
        surface: '0 0 0 1px rgba(255,255,255,0.06)',
        raised: '0 0 0 1px rgba(255,255,255,0.08), 0 4px 16px rgba(0,0,0,0.35)',
        overlay: '0 0 0 1px rgba(255,255,255,0.08), 0 16px 48px rgba(0,0,0,0.50)',
        // Anneau focus unique pour toute l'app (focus-visible:shadow-focus).
        focus: '0 0 0 2px #0a0b10, 0 0 0 4px rgba(110,86,247,0.60)',
        // Back-compat : .glass → hairline + ombre courte.
        glass: '0 0 0 1px rgba(255,255,255,0.06), 0 1px 2px rgba(0,0,0,0.30)',
        'glass-soft': '0 0 0 1px rgba(255,255,255,0.05)',
        // Glows → rings discrets (plus de halos 26-30px).
        'glow-green': '0 0 0 1px rgba(76,195,138,0.32), 0 0 12px rgba(76,195,138,0.12)',
        'glow-amber': '0 0 0 1px rgba(217,168,60,0.32), 0 0 12px rgba(217,168,60,0.12)',
        'glow-orange': '0 0 0 1px rgba(232,128,79,0.32), 0 0 12px rgba(232,128,79,0.12)',
        'glow-coral': '0 0 0 1px rgba(232,128,79,0.32), 0 0 12px rgba(232,128,79,0.12)',
        'glow-red': '0 0 0 1px rgba(229,83,75,0.35), 0 0 14px rgba(229,83,75,0.14)',
        'glow-cyan': '0 0 0 1px rgba(110,86,247,0.32), 0 0 12px rgba(110,86,247,0.12)',
        'glow-violet': '0 0 0 1px rgba(155,139,255,0.32), 0 0 12px rgba(155,139,255,0.12)',
        'glow-blue': '0 0 0 1px rgba(110,86,247,0.32), 0 0 12px rgba(110,86,247,0.12)',
        'glow-purple': '0 0 0 1px rgba(155,139,255,0.32), 0 0 12px rgba(155,139,255,0.12)',
      },
      borderRadius: {
        glass: '12px', // cartes/panneaux (était 22px)
        pill: '999px', // badges, pills
      },
      backgroundImage: {
        // Un seul wash ultra-subtil en haut de page — fini les auroras.
        'aurora-1':
          'radial-gradient(80% 40% at 50% 0%, rgba(110,86,247,0.05) 0%, transparent 70%)',
        'aurora-2':
          'radial-gradient(60% 30% at 50% 100%, rgba(155,139,255,0.03) 0%, transparent 70%)',
        // Tiles : fonds plats teintés très bas — la sévérité se lit via badge/bordure.
        'tile-good':
          'linear-gradient(180deg, rgba(76,195,138,0.07) 0%, rgba(76,195,138,0.02) 100%)',
        'tile-warn':
          'linear-gradient(180deg, rgba(217,168,60,0.08) 0%, rgba(217,168,60,0.02) 100%)',
        'tile-bad':
          'linear-gradient(180deg, rgba(229,83,75,0.09) 0%, rgba(229,83,75,0.03) 100%)',
        'tile-info':
          'linear-gradient(180deg, rgba(110,86,247,0.07) 0%, rgba(110,86,247,0.02) 100%)',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        pulseGlow: {
          '0%, 100%': { opacity: '0.55' },
          '50%': { opacity: '1' },
        },
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
      animation: {
        shimmer: 'shimmer 2.4s linear infinite',
        'pulse-glow': 'pulseGlow 2.4s ease-in-out infinite',
        'fade-up': 'fadeUp 200ms cubic-bezier(0.16, 1, 0.3, 1)',
        'fade-in': 'fadeIn 150ms ease-out',
      },
    },
  },
  plugins: [],
};
export default config;

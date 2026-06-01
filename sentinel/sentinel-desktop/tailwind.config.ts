import type { Config } from 'tailwindcss';

// Sentinel MCP — palette inspired by CleanMyMac X.
// Warm dark base, vibrant green / amber / coral accents, gradient hero washes.

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx,js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          // Status palette — saturated, slightly warm
          green: '#34d399',
          'green-glow': '#10b981',
          amber: '#fbbf24',
          'amber-glow': '#f59e0b',
          coral: '#fb7185',
          'coral-glow': '#f43f5e',
          red: '#ef4444',
          'red-glow': '#dc2626',
          cyan: '#22d3ee',
          'cyan-glow': '#06b6d4',
          violet: '#a78bfa',
          'violet-glow': '#8b5cf6',
          // Back-compat aliases for components written against the older palette.
          blue: '#22d3ee',
          'blue-glow': '#06b6d4',
          purple: '#a78bfa',
          'purple-glow': '#8b5cf6',
          // Background layers — warm dark navy
          ink: '#0a0e1a',
          mid: '#10162a',
          deep: '#070a14',
          // Surfaces — more opaque than pure glass for that CMM feel
          glass: 'rgba(255, 255, 255, 0.05)',
          'glass-strong': 'rgba(22, 30, 52, 0.72)',
          'glass-border': 'rgba(255, 255, 255, 0.10)',
          'glass-line': 'rgba(255, 255, 255, 0.06)',
          // Text — bright white for that CMM crispness
          'text-primary': '#f9fafb',
          'text-secondary': 'rgba(249, 250, 251, 0.70)',
          'text-tertiary': 'rgba(249, 250, 251, 0.42)',
        },
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
      backdropBlur: {
        xs: '4px',
        glass: '20px',
        'glass-strong': '32px',
      },
      boxShadow: {
        glass:
          '0 1px 0 rgba(255,255,255,0.08) inset, 0 0 0 1px rgba(255,255,255,0.06), 0 8px 24px rgba(0,0,0,0.45)',
        'glass-soft':
          '0 1px 0 rgba(255,255,255,0.06) inset, 0 0 0 1px rgba(255,255,255,0.05), 0 4px 12px rgba(0,0,0,0.30)',
        'glow-green': '0 0 26px rgba(52,211,153,0.50)',
        'glow-amber': '0 0 26px rgba(251,191,36,0.55)',
        'glow-coral': '0 0 30px rgba(251,113,133,0.55)',
        'glow-red':   '0 0 30px rgba(239,68,68,0.55)',
        'glow-cyan':  '0 0 30px rgba(34,211,238,0.55)',
        'glow-violet':'0 0 30px rgba(167,139,250,0.55)',
        // Aliases for back-compat
        'glow-blue':   '0 0 30px rgba(34,211,238,0.55)',
        'glow-purple': '0 0 30px rgba(167,139,250,0.55)',
      },
      borderRadius: {
        glass: '22px',
        pill: '999px',
      },
      backgroundImage: {
        // Warm cinematic gradient: teal → violet → coral wash
        'aurora-1':
          'radial-gradient(60% 50% at 18% 12%, rgba(34,211,238,0.30) 0%, transparent 60%), radial-gradient(50% 50% at 92% 22%, rgba(167,139,250,0.32) 0%, transparent 60%), radial-gradient(55% 60% at 70% 92%, rgba(251,113,133,0.22) 0%, transparent 60%)',
        'aurora-2':
          'radial-gradient(40% 40% at 30% 80%, rgba(251,191,36,0.22) 0%, transparent 70%), radial-gradient(40% 40% at 80% 30%, rgba(52,211,153,0.18) 0%, transparent 70%)',
        // CMM-style hero gradient on tiles
        'tile-good':
          'linear-gradient(135deg, rgba(52,211,153,0.18) 0%, rgba(34,211,238,0.06) 100%)',
        'tile-warn':
          'linear-gradient(135deg, rgba(251,191,36,0.22) 0%, rgba(251,113,133,0.08) 100%)',
        'tile-bad':
          'linear-gradient(135deg, rgba(239,68,68,0.26) 0%, rgba(251,113,133,0.10) 100%)',
        'tile-info':
          'linear-gradient(135deg, rgba(167,139,250,0.20) 0%, rgba(34,211,238,0.08) 100%)',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        pulseGlow: {
          '0%, 100%': { opacity: '0.72' },
          '50%': { opacity: '1' },
        },
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        shimmer: 'shimmer 2.4s linear infinite',
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'fade-up': 'fadeUp 280ms cubic-bezier(0.4, 0, 0.2, 1)',
      },
    },
  },
  plugins: [],
};
export default config;

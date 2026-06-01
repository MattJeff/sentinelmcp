# Sentinel MCP — Design System (WWDC26 Glass)

**Authoritative for every UI agent. Read this before writing any component.**

## North star

A frosted, layered Mac-native feel. Aurora gradient backdrop. Frosted-glass
panels everywhere. Vibrant accents on status (green/orange/red/blue/purple).
Quiet typography. Lots of whitespace. Smooth motion under 250 ms.

## Tokens (Tailwind already wired in `tailwind.config.ts`)

### Colors

| Token | Usage |
|---|---|
| `sentinel-green` / `-glow` | Approved / safe / OK |
| `sentinel-orange` / `-glow` | Unknown / suspect / medium severity |
| `sentinel-red` / `-glow` | Rug-pull / poisoning / critical |
| `sentinel-blue` / `-glow` | Primary actions, primary accent |
| `sentinel-purple` | Secondary accent, aurora |
| `sentinel-ink` / `-mid` / `-fog` | Background layers |
| `sentinel-glass` / `-strong` / `-border` | Frosted surfaces |
| `sentinel-text-primary` / `-secondary` / `-tertiary` | Typography |

### Surfaces

- `.glass` — primary panel (24 px backdrop blur)
- `.glass-strong` — sidebar + main shell (40 px backdrop blur)
- `.glass-soft` — nested surfaces (12 px backdrop blur)
- `.card` — standard panel
- `.card-hover` — interactive panel with hover lift

### Components

- `.pill .pill-{green|orange|red|blue}` — status pills
- `.dot .dot-{green|orange|red}` — status dot with glow
- `.btn .btn-primary .btn-danger` — buttons
- `.input` — text input
- `.section-heading` — uppercase 10 px tracking
- `.skeleton` — shimmer placeholder
- `.titlebar` / `.no-drag` — macOS drag region

### Motion

- Enter: `animate-fade-up` (280 ms)
- Pulse: `animate-pulse-glow`
- Shimmer: `animate-shimmer`
- Hover lifts: `translateY(-2px)` over 220 ms

## Layout rules

1. **Frosted shell**: sidebar + main are `.glass-strong`. Page content is on top.
2. **Card grids**: 3-column at >=1280 px, 2 at >=900, 1 below.
3. **Spacing**: page padding `p-6`. Inner card padding `p-5`. Vertical rhythm `gap-4` or `gap-6`.
4. **Borders**: only via `.glass*` classes — no extra borders.
5. **Shadows**: prefer `shadow-glass` / `shadow-glass-soft`. Use `shadow-glow-*` for accents only.

## Typography

- Display: 28 px / semibold (page H1)
- Section: 15 px / semibold (panel title)
- Body: 13 px / regular
- Caption: 11 px / 10 px tracking-wide uppercase (section heading)
- Mono: status hashes, code, JSON

## Iconography

`lucide-react` only. 16 px by default, 14 px in dense rows, 20 px in heroes.

## States

- **Approved**: `dot-green` + `pill-green` label "Approved"
- **Unknown**: `dot-orange` + `pill-orange` label "Unknown"
- **Suspect / Rug-pull / Critical**: `dot-red` + `pill-red`
- **Approved with caveat**: green dot + small orange marker

## Localisation

UI strings are **English**, US format. Compliance identifiers stay as-is
(MCP09, SAFE-T1201, …). Dates in `Apr 12, 14:32`.

## Anti-patterns

- No flat solid panels — always use the glass classes.
- No raw borders or shadows outside the tokens.
- No emoji in UI labels.
- No spinners on quick actions — use shimmer + fade-up.
- No modal that isn't frosted-glass.

## Data contract

All data comes through `@/api/tauri` which is typed against `@/api/contract.ts`.
**Never call `invoke` directly from a component.**

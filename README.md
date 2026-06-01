# Sentinel MCP

> See every MCP server your AI agents reach. Detect rug-pulls, tool poisoning, and supply-chain attacks before they hit production.

Sentinel MCP is a native macOS app that discovers every Model Context Protocol (MCP) server installed on your machine across all major AI clients (Claude Desktop, Claude Code CLI, Cursor, Windsurf, Continue, Zed, VS Code, Aider, Goose, Codex, Antigravity, LM Studio), actively probes each one, computes a cryptographic fingerprint of its tool surface, watches for drift across sessions, maps every finding to OWASP MCP09/MCP03 + SAFE-MCP T1001/T1201, and produces a signed Ed25519 compliance bundle ready for an auditor.

**Read-only by default. Nothing leaves your Mac.**

---

## Download

The latest signed-on-build `.dmg` lives in **[Releases](https://github.com/MattJeff/sentinelmcp/releases/latest)**.

```
Sentinel MCP_0.1.0_aarch64.dmg   ~10.6 MB
SHA-256: aaf398196ed43e27ae384f6995afc934bb927bcd886a914340fee159e35c2b9e
```

Double-click → drag into `/Applications` → launch. On first launch Sentinel asks for permission to read the AI-client config files listed below; nothing else.

---

## What it does

### 1. Discovery — finds every MCP server your machine declares

Sentinel walks 12 well-known config locations and parses each:

| AI client | Config file |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code CLI | `~/.claude.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Continue.dev | `~/.continue/config.yaml` |
| Zed | `~/.config/zed/settings.json` |
| VS Code | `~/Library/Application Support/Code/User/settings.json` |
| Aider | `~/.aider.conf.yml` |
| Goose | `~/.config/goose/config.yaml` |
| Codex CLI | `~/.codex/config.toml` |
| Antigravity | `~/Library/Application Support/Antigravity/User/settings.json` |
| LM Studio | `~/.lmstudio/mcp.json` |

It also auto-detects installed apps via `/Applications` + reads their version from `Info.plist`.

### 2. Active probe — talks to every declared server

For each declared stdio server, Sentinel spawns it in a sandbox, runs the standard MCP handshake (`initialize` → `notifications/initialized` → `tools/list`), captures the full tool list with `inputSchema`, computes a **canonical SHA-256 fingerprint** (sorted keys, stable encoding), and runs poisoning patterns on every description and schema.

This is what distinguishes Sentinel from a config grep: you see what the server actually exposes at runtime, not what its config claims.

### 3. Continuous monitoring — live by default

A tokio task re-runs Discovery + Active Probe every N seconds (default 30, configurable in Settings). A `notify` file watcher arms every config path; the moment you run `claude mcp add foo`, Sentinel sees it in ~300 ms with zero user action. The "Live · 30s" pulsing badge in the sidebar reflects the cadence.

### 4. Four security differentiators

| | What it does |
|---|---|
| **Active probe** | Launches each server, fingerprints its tool surface, detects poisoning live |
| **Supply-chain attestation** | Queries the npm registry, captures SHA-512 tarball hashes, maintainers, publish date |
| **Threat intelligence feed** | 17 curated entries: typo-squats, SAFE-T1001 poisoning, SAFE-T1201 rug-pulls, revoked maintainers. Cross-references against your inventory in real time |
| **Trust graph + blast radius** | Typed graph of `AI client → MCP server → scope (filesystem, secrets, network, …)` with a 0–10 risk score per client. Pinpoints which agent would bleed the most if compromised |

### 5. Signed compliance bundle

One click in the Report tab → PDF + JSON + Ed25519 signature. Every constat maps to:

- **OWASP MCP09** (Shadow MCP Server)
- **OWASP MCP03** (Tool Poisoning)
- **SAFE-T1001** (Tool Description Poisoning)
- **SAFE-T1201** (Rug Pull / Tool Behavior Change)
- **SOC 2** (CC6.1, CC7.1, CC7.2)
- **ISO 27001** (A.8.1.1, A.12.4.1, A.12.6.1, A.13.1.1, A.14.2.2, …)

---

## The 11 pages

| Page | What you do here |
|---|---|
| **Overview** | KPI tiles: servers detected, at risk, critical findings, time-to-first-red. Recent findings feed. Compliance snapshot |
| **Inventory** | Every server with its tools, fingerprint, scopes, status. Click a card → drawer with Approve / Investigate / Block |
| **Discovery** | Every AI client found on your Mac with the MCP servers it declares. Threat intel feed at the bottom |
| **Live Scan** | One-shot or live probe of every declared server with streaming log + KPI tiles |
| **Alerts** | Rug-pulls, poisoning, sosies, exfiltration with the diff that triggered them. Filtered by severity + channel |
| **Approvals** | Approve fixes the baseline fingerprint. Investigate marks limbo. Block raises the status |
| **Trust graph** | Interactive force-directed graph; per-client blast radius bar sorted desc |
| **Time travel** | Replay every JSON-RPC envelope ever observed (with `tools/call` arguments redacted) |
| **Compliance** | Framework coverage with clickable identifiers that open the official spec |
| **Report** | Generate a signed PDF + JSON bundle. Open with the system PDF viewer |
| **Settings** | Persisted to `~/Library/Application Support/com.sentinel-mcp.desktop/settings.toml`. Channels, retention, scan mode, live interval |

---

## Architecture

```
[ AI agent traffic ]
        │
        ▼
[ Capteur ]  ── passive local capture, read-only by default
        │  • stdio wrapper      (sentinel-scan)
        │  • HTTP proxy local
        ▼
[ Pipeline ]
   ├─ Coarse JSON-RPC filter
   ├─ MCP signature confirmation
   ├─ tools/list parser
   ├─ Canonical SHA-256 fingerprint   (sentinel-detect)
   ├─ Poisoning pattern library       (37 patterns, 5 categories)
   ├─ Rug-pull diff engine
   ├─ Exfiltration combo detector
   ├─ Lookalike + SBOM verifier
   └─ Continuous monitor               (sentinel-monitor)
        │
        ▼
[ SQLite store ]   ~/Library/Application Support/com.sentinel-mcp.desktop/sentinel.db
        │
        ▼
[ Tauri + React UI ]  11 pages, glass-style WWDC26 / CleanMyMac palette
```

### Workspace layout

```
sentinel/                       — Rust workspace
├── crates/
│   ├── sentinel-protocol/      Shared types (zero logic)
│   ├── sentinel-store/         SQLite store with anti-leak guarantees
│   ├── sentinel-scan/          Capture, signature, parser, scope detector
│   ├── sentinel-monitor/       Baselines, drift, retention, privacy
│   ├── sentinel-detect/        Canonical hash, diff, poisoning, rug-pull, exfiltration, lookalikes, corpus
│   ├── sentinel-alerts/        Engine, severity, channels (dashboard/email/webhook/siem), enrichment, dedup, lifecycle
│   ├── sentinel-report/        Generator, summary, inventory, compliance, signature, PDF, JSON, dashboard, approval, remediation
│   ├── sentinel-discovery/     12 client sources + active probe + supply chain + threat intel + trust graph
│   └── sentinel-cli/           Command-line entry point
└── sentinel-desktop/           Tauri 2 + React 19 + Vite + Tailwind app
    ├── src/                    Frontend
    └── src-tauri/              Native shell + Tauri commands + background live loop
```

---

## Build from source

### Prerequisites
- Rust ≥ 1.77 (`rustup install stable`)
- Node 20+ and pnpm 10
- Xcode Command Line Tools (`xcode-select --install`)

### Steps
```bash
git clone https://github.com/MattJeff/sentinelmcp.git
cd sentinelmcp/sentinel/sentinel-desktop
pnpm install
pnpm tauri build --bundles dmg
```

Output : `src-tauri/target/release/bundle/dmg/Sentinel MCP_0.1.0_aarch64.dmg`.

### Run the Rust workspace tests
```bash
cd sentinel
cargo test --workspace --no-fail-fast
# 377 tests passing
```

### Live end-to-end probe on your own machine
```bash
cd sentinel
cargo run -p sentinel-discovery --example smoke_e2e
```
Sample output (this machine, after installing `orizn-visa` via `claude mcp add`):
```
detected clients : 7
declared servers : 2 (chrome-devtools, orizn-visa)
active probe     : 2/2 success
  chrome-devtools = 29 tools (2008 ms)
  orizn-visa      = 5 tools  (1546 ms)
trust graph      : Claude Code CLI blast_radius=2/2
threat intel     : 17 entries
```

---

## Privacy guarantees

- **Read-only by default.** Sentinel never modifies your AI-client configs.
- **Inspection in flight, no payload storage.** `params.arguments` of `tools/call` are never written to disk. This is enforced in `sentinel-monitor::privacy`.
- **No outbound calls** outside the optional npm registry attestation. The threat intel feed ships embedded in the binary via `include_str!`.
- **No telemetry.** Sentinel has zero analytics, zero crash reporting, zero phone-home.
- The SQLite store lives at `~/Library/Application Support/com.sentinel-mcp.desktop/sentinel.db` and is yours alone.

---

## Why this exists

> In 2012 the Shadow IT problem was an employee dropping files into Dropbox.
> In 2026 the Shadow MCP problem is an AI agent reaching out to MCP servers nobody audited.

Up to 15 lookalike packages exist per official MCP server on public registries.
88 % of organisations surveyed reported an agent-related incident in the last 12 months.
The OWASP MCP Top 10 and SAFE-MCP framework codified the threat — there was no light-weight tool that surfaced it on a developer's own machine.

Sentinel MCP is that tool.

---

## License

MIT.

---

## Compliance references

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) — MCP09 (Shadow MCP), MCP03 (Tool Poisoning)
- [SAFE-MCP](https://safemcp.io/) — T1001 (Tool Description Poisoning), T1201 (Rug Pull)
- SOC 2 — CC6.1, CC7.1, CC7.2
- ISO 27001 — A.8.1.1, A.12.4.1, A.12.4.3, A.12.6.1, A.13.1.1, A.14.2.2

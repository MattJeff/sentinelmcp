# Quickstart

Get from zero to a full MCP security posture in under five minutes: a 60-second local scan, an automated audit in CI, and continuous guard mode.

---

## 1. Scan in 60 seconds

### Install the CLI

Pick one:

```bash
# One-liner installer
curl -fsSL https://sentinelmcp.dev/install.sh | sh

# Homebrew
brew install MattJeff/sentinel/sentinel

# Cargo (builds from source)
cargo install --git https://github.com/MattJeff/sentinelmcp sentinel-cli
```

Verify:

```bash
sentinel --version
```

Pre-built binaries are published for macOS and Linux (x86_64 + ARM64) and Windows (x86_64) — see [INSTALL.md](INSTALL.md) for every target and SHA-256 checksum verification.

### Discover

```bash
sentinel scan
```

Sentinel reads — locally, read-only — the configuration of every AI client installed on your machine (Claude Desktop, Claude Code CLI, Cursor, Windsurf, Continue, Zed, VS Code, Aider, Goose, Codex, Antigravity, LM Studio, Open WebUI, Sketch) and lists every MCP server they declare, including whether each server is scoped to your user account or to a specific project directory.

```
Scan complete · 7 clients · 12 declared servers

  Claude Code CLI   ~/.claude.json                       5 servers (3 user, 2 project)
  Claude Desktop    ~/Library/Application Support/...    3 servers
  Cursor            ~/.cursor/mcp.json                   4 servers
  ...
```

### Probe

```bash
sentinel scan --probe
```

For each declared server, Sentinel spawns the actual MCP executable (stdio) or opens a Streamable HTTP session, performs the standard handshake (`initialize` → `tools/list`), and captures the **real** tool inventory — names, descriptions, full input schemas. It then:

- computes a **canonical SHA-256 fingerprint** of the tool surface,
- runs the **hybrid local poisoning engine** over every description and schema — 40+ regex patterns + Unicode anti-smuggling (zero-width, bidi, Tags block, ANSI) + NFKC normalization + line-jumping + embedded **YARA** rules,
- cross-references the inventory against the bundled **threat-intel feed**,
- flags **secret-read + network-write** scope combinations.

No tool is ever executed; the probe is handshake-only and closes the process cleanly.

YARA is on by default; toggle the engines with flags (and an optional **local** LLM judge via Ollama — opt-in, localhost-only, zero cloud):

```bash
sentinel scan --probe --no-yara          # disable the YARA engine
sentinel scan --probe --llm              # add a local LLM second opinion (Ollama)
sentinel scan --probe --llm --llm-url http://localhost:11434
```

The same engines are exposed in the desktop app under **Settings → Detection engines** (YARA toggle, local LLM-judge toggle + endpoint, and a read-only list of the embedded YARA rules).

### Report

```bash
sentinel report
```

Generates the signed audit bundle: an executive-summary PDF, a structured JSON export, and an **Ed25519 signature** verifiable offline (signing is on by default, the key is sealed in the OS keychain). Every finding is mapped to SOC 2, ISO 27001, OWASP MCP, SAFE-MCP, OWASP ASI and — where clearly applicable — MITRE ATT&CK / ATLAS control identifiers — ready to hand to an auditor as-is.

---

## 2. Audit in CI with the GitHub Action

Catch a poisoned or rug-pulled MCP server before it merges. Add this to `.github/workflows/mcp-audit.yml`:

```yaml
name: MCP security audit

on:
  pull_request:
  schedule:
    - cron: "0 6 * * *"   # daily drift check

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: MattJeff/sentinelmcp/action@v1
        with:
          # Fail the job if any finding at or above this severity is raised
          fail-on: critical          # critical | high | medium | low

          # Probe declared servers actively (handshake-only)
          probe: true

          # Path(s) to MCP configs to audit (project-scope configs in the repo)
          config-glob: "**/.mcp.json,**/mcp_config.json"

          # Optional: compare against a committed baseline to detect rug-pulls
          baseline: .sentinel/baseline.json
```

Typical workflow:

1. **First run** — generate and commit the baseline:
   ```bash
   sentinel scan --probe --write-baseline .sentinel/baseline.json
   git add .sentinel/baseline.json && git commit -m "chore: MCP baseline"
   ```
2. **Every PR** — the action re-probes the declared servers and diffs the canonical fingerprints against the baseline. Any drift (added tool, changed description, widened enum, modified default) fails the check with a tool-by-tool diff in the job summary.
3. **Nightly schedule** — catches rug-pulls that happen upstream between PRs.

The action runs fully inside the runner: no token, no cloud account, nothing uploaded.

### Or audit a repo directly

If you'd rather not probe live servers, `sentinel audit <path>` statically scans a checkout for MCP configs (`mcp.json`, `.mcp.json`, `mcp_config.json`, `claude_desktop_config.json`) and reports findings — no probing, no database, ideal for CI:

```bash
sentinel audit .                 # scan the working tree
sentinel audit . --json          # machine-readable output
```

It flags, statically and locally:

- **tool poisoning** in declared definitions (patterns + Unicode anti-smuggling + YARA),
- **typosquats** of official packages (canonical `package_id` + Jaro-Winkler),
- **cleartext transport** — an `http://` endpoint to a remote host (loopback is exempt),
- **hard-coded secrets** — only high-confidence, structured token formats (OpenAI/Anthropic, GitHub PAT, Slack, AWS, Google…), never bare values, so secrets referenced indirectly (`${VAR}`, `op://`, `vault:`…) are not false-flagged,
- **shell-injection** arguments (chained metacharacters into a shell/network binary).

Exit code is `0` (no finding), `1` (a high/critical finding — fail the build), or `2` (execution error). `--yara`/`--no-yara`/`--llm`/`--llm-url` apply here too.

---

## 3. Guard mode — continuous monitoring

A one-shot scan misses tomorrow's rug-pull. Guard mode keeps Sentinel running in the background:

```bash
sentinel guard
```

What it does, continuously:

- **File watching** — every AI-client config path is armed with a file watcher. Run `claude mcp add foo` and the new server appears in the inventory in **under 500 ms**, no rescan needed.
- **Periodic sweep** — a light discovery + probe pass every 10/30/60 s (configurable), re-checking fingerprints against approved baselines.
- **Drift alerts** — any divergence from a baseline raises a finding with a readable diff and dispatches it to the channels you configured: dashboard, email, webhook (Slack/Teams), **Splunk HEC**, **Elasticsearch**, or **Syslog UDP/TCP/TLS (RFC 5425)**.
- **Threat-feed refresh** — the curated feed of malicious MCP packages refreshes in the background (24 h cooldown, `remote → disk cache → bundled` cascade) so matching keeps working offline.

On macOS, the desktop app provides the same guard loop with a menubar icon, an open-alerts counter, and a `⌘K` command palette. Closing the window keeps monitoring alive in the tray.

### Privacy defaults

- **Outbound calls are OFF by default.** Until you enable the single global gate in Settings, no SIEM, TAXII, email, webhook, registry lookup or feed refresh ever leaves the machine.
- **Read-only by default.** Sentinel never modifies a client config unless you explicitly enable enforcement mode — and even then it writes a timestamped backup with one-click restore.
- **Inspection in flight.** Message bodies are never persisted by default; only headers and sizes.

### Approving servers

Guard mode is most useful once you have approved your known-good servers:

```bash
sentinel list                    # inventory with fingerprints and statuses
sentinel approve <server-id>     # freeze the current fingerprint as the baseline
sentinel block <server-id>       # mark as blocked (advisory; enforcement is opt-in)
```

From that point, **any** change to an approved server's tool surface — however subtle — is a finding.

---

## Next steps

- [README](../README.md) — capability overview and architecture
- [COMPARISON](COMPARISON.md) — how Sentinel stacks up against every other MCP security tool
- [Full feature reference](../sentinel/FEATURES.md) — every page, detector and setting in depth

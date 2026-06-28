# Changelog

All notable changes to Sentinel MCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions below track the Rust workspace (CLI and detection crates). The desktop
app (`sentinel-desktop`) is versioned separately via its own
`Cargo.toml` / `package.json` / `tauri.conf.json` and is currently at 0.6.0.

## [0.8.0] - 2026-06-28

Runtime defenses plus extended coverage. Every new capability was attacked by a
skeptical agent that fixed false positives/negatives before integration
(`cargo test --workspace`: 999 tests, 0 failure; desktop check: 0 warning).

### Added
- **Lethal trifecta** (`sentinel-detect`): a CRITICAL finding when the three legs
  (untrusted input + secret read + external write) co-occur in a single session.
- **Cross-server tool shadowing** (`sentinel-detect`): detects tool-name collisions
  between servers and descriptions that instruct about another server's tool.
- **Offline CVE/OSV matching** (`sentinel-detect`): embedded database (mcp-remote
  CVE-2025-6514 9.6, MCP Inspector CVE-2025-49596, EscapeRoute, Python SDK…) with
  simple semver and exclusive upper bound.
- **Proxy output scanning** (`sentinel-scan`): scans tool outputs/errors in the
  real-time proxy to catch runtime ATPA / toxic-flow attacks invisible to static scans.
- **Approve-before-run policy** (`sentinel-scan`): per `tools/call` risk classification
  with an opt-in `enforce` mode (refuse/hold a high-risk call). Detection first,
  blocking opt-in; bit-exact relay preserved by default.
- **Project-scope config baseline + diff** (`sentinel-discovery`) for CVE-2025-54136 (MCPoison).
- **Static OAuth/SSRF checks** (`sentinel-discovery`) for HTTP servers: token
  passthrough, missing RFC 8707 audience, private/loopback IPs.
- **`runtime_inspector`** (`sentinel-discovery`): portable enumeration of listening
  sockets (anti-NeighborJack, servers launched outside config); defensive lsof/ss parsing.
- **Fuzzy threat-feed matching** (`sentinel-discovery`): case-insensitive +
  Levenshtein ≤2 with conservative thresholds.

### Changed
- Poisoning detection extended to `resources/list` and `prompts/list`.

### Fixed
- Anti-false-positive token bounds so `extract_keywords` / `count_tokens` are no
  longer mistaken for secrets; UTF-8 panic-safe extracts; legitimate emoji ZWJ
  neutralized on both poisoning paths.
- Proxy response detection no longer short-circuited by a stray `method` field
  (false negative); UTF-8 panic on non-JSON log line fixed; malformed `fixed`
  CVE bound guarded; `auth=bearer/none` no longer treated as a secret.

## [0.7.0] - 2026-06-28

P0/P1 hardening, hybrid detections wired in, and UX/pedagogy work derived from a
full code audit plus MCP security research (12 crates, frontend), applied in
verified waves (`cargo test --workspace`: 910 tests, 0 failure; desktop check:
0 warning; `tsc`: 0 error).

### Added
- Unicode anti-smuggling (zero-width/bidi/Tags/ANSI) with NFKC normalization.
- Line-jumping patterns (secret request, compliance pressure, fake OS identity, urgency).
- Unicode UTS#39 confusables for lookalike (homoglyph) detection.
- Hybrid engines finally wired in: YARA + local LLM judge (Ollama) via
  `InspecteurPoisoning::inspecter_complet` (previously orphaned) — zero-cloud by default.
- Supply-chain attestation: version-level rug-pull detection (the Postmark case).
- Security scan of discovered skills/agents.
- Transport/secrets/injection auditor (`sentinel audit`).
- SAFE-MCP / OWASP MCP / ASI / ATT&CK mapping with an honest coverage matrix.
- Hybrid detection surfaced in the app (live scan + probe), not only in the CLI.
- CLI flags `--yara` / `--no-yara` / `--llm` / `--llm-url` on `scan` and `audit`.
- Tauri commands `list_yara_rules`, `compliance_coverage`, `scan_skills`, and a
  "Detection engines" settings panel (YARA/LLM toggles).
- Frontend: category badges and explanatory tooltips, readable rug-pull diff,
  coverage matrix, skills security panel.

### Changed
- Docs (README/QUICKSTART/COMPARISON/DETECTION-MATRIX/FEATURES) updated for accuracy
  (the "hybrid engines" gap is closed).

### Fixed
- `sentinel-report`: Ed25519 signature actually applied (OS-keyring-sealed key with
  ephemeral fallback), collision-resistant canonical payload, PDF generation wired
  (the "signed reports" promise was a no-op).
- `sentinel-scan`: SSE messages lost at chunk boundaries (EDR false negative) fixed
  with a persistent buffer; poison-tolerant mutexes (anti-DoS); serialization-failure logging.
- `sentinel-detect`: UTF-8 panic on untrusted tool description (detector DoS) fixed
  via character boundaries; `f64` sort via `total_cmp`; poison-tolerant mutexes.
- `sentinel-store`: empty endpoint rejected (protects the V4 unique index); GC guard ≥1.
- `sentinel-monitor`: canonical fingerprint (reuses `detect::canonicaliser_json`) to
  avoid drift false positives; failure logging; poison-tolerant mutexes.
- `sentinel-alerts`: SIEM unknown severity and compliance reference propagation;
  keyring secret resolution in sinks; poison-tolerant mutexes.
- `sentinel-stix`: deterministic bundle (sorted objects) for TAXII idempotence.
- `sentinel-discovery`: skills-discovery failure logging (no more silent false negative).
- `sentinel-cli`: table-render underflow guard; `--quiet` honored on `monitor`.
- Frontend: `proxy_stop` → `stop_proxy` (broken proxy stop fixed).

[0.8.0]: https://github.com/MattJeff/sentinelmcp/releases/tag/v0.8.0
[0.7.0]: https://github.com/MattJeff/sentinelmcp/releases/tag/v0.7.0

# Sentinel MCP vs. the field

A detailed comparison of Sentinel MCP against every notable MCP security tool, open-source and commercial, as of June 2026.

The category Sentinel occupies is **MCP Detection & Response (MCPDR)**: continuous discovery, fingerprinting, drift detection and SOC integration for the MCP servers your AI agents actually use — on the endpoint, where Claude Desktop, Cursor and their servers actually live.

---

## The matrix

| Capability | **Sentinel** | mcp-scan / Snyk Agent Scan | ToolHive (Stacklok) | mcp-watch | MCP Guardian (eqtylab) | Cisco mcp-scanner | Commercial (Proofpoint, JFrog, Wiz, Qualys, Prisma AIRS) |
|---|---|---|---|---|---|---|---|
| Multi-client discovery | **14 clients + skills/agents (user/project/extension scopes)** | 13 agents (+ skills, 4 config scopes) | No (manages its own servers) | No (single URL/repo) | No (manual proxy) | Partial (configs) | Yes (cloud/SaaS/endpoint) |
| Active probing (`tools/list`) | **Yes** | Yes (consent required) | N/A (containerized) | No (static) | Via proxy | Yes | Varies |
| Persistent cross-session baselines | **Yes (canonical SHA-256 + package_id)** | Description hashes only | No | No | No | No | Cloud inventory |
| Continuous runtime detection | **Real-time stdio proxy: arg poisoning, exfil combos + lethal trifecta, sampling abuse, runtime-output/error scan (ATPA), approve-before-run (opt-in enforce) + periodic scan + file watcher** | Real-time proxy mode | Yes (gateway, OIDC, per-tool policies) | No | Yes (live approvals) | No | Yes (traffic) |
| Known-vulnerable package / CVE matching | **Offline embedded CVE base (6 MCP CVEs) by package+version + MCPoison config-content diff (CVE-2025-54136)** | No | No | No | No | No | Partial (JFrog/Wiz) |
| Cross-server tool shadowing | **Name collision + cross-server poisoning (SAFE-T1102)** | No | No | No | No | No | Rare |
| OAuth / SSRF static checks (HTTP servers) | **SSRF/cloud-metadata (CWE-918), confused deputy (RFC 8707), token passthrough (CWE-522)** | No | Indirect (gateway) | No | No | No | Partial |
| Tool poisoning | **Hybrid local engine, wired in CLI + UI: 40+ patterns + Unicode anti-smuggling/NFKC + line-jumping + YARA (yara-x) + optional Ollama LLM judge** | Yes (cloud LLM, Snyk token required) | Indirect | Yes | Basic checks | Yes (YARA + LLM-judge) | Yes |
| Lookalikes / typosquatting | **Jaro-Winkler + Unicode confusables (UTS#39 skeleton), 4 registries** | No | No | No | No | No | Partial (JFrog) |
| Supply-chain attestation (npm integrity) | **Yes (SHA-512, maintainers, publish date, pinned version + version-level rug-pull diff)** | No | No | No | No | No | Partial (JFrog) |
| Exfiltration combos | **Yes** | "Toxic flows" | No | Yes (basic) | No | No | Yes |
| SIEM (Splunk / Elastic / Syslog TLS) | **Native** | No (Snyk platform) | OTel/observability | No | No | No | Yes |
| STIX 2.1 / TAXII 2.1 | **Yes** | No | No | No | No | No | Rare |
| Signed compliance reports (Ed25519, SOC 2/ISO/OWASP/SAFE-MCP) | **Yes** | No | No | No | No | No | Dashboards |
| Desktop multi-OS + CLI/CI | Yes (Rust, notarized) | Python CLI (uv + token) | CLI/K8s/Studio | Node CLI | Desktop | Python CLI | Agents/SaaS |
| License / pricing | Product | Apache-2.0 free + paid Snyk platform | Apache-2.0 free | MIT | Apache-2.0 (inactive since 08/2025) | Apache-2.0 | Enterprise $$$ |
| Traction (GitHub stars) | — | **2,552** | 1,870 | 132 | 199 (abandoned) | 961 | Strong (enterprise GTM) |

---

## Where Sentinel is already ahead

1. **Persistent canonical baselines.** Sentinel fingerprints the *entire* tool surface (sorted-keys canonical JSON, full input schemas included) with SHA-256, ties it to a cross-session `package_id` identity, and persists it at approval time. mcp-scan only hashes descriptions. Result: rug-pull detection that survives renames, package migrations, and schema-level tampering (widened enums, changed defaults) that description hashes miss entirely.

2. **STIX 2.1 + TAXII 2.1.** No open-source competitor — and few commercial ones — exports MCP findings to CTI platforms. Sentinel serializes findings as STIX 2.1 bundles and pushes them to any TAXII 2.1 collection, plugging straight into SOC/GRC/TIP workflows without reprocessing. Unique on the market.

3. **Native SIEM with zero cloud.** Splunk HEC, Elasticsearch, and Syslog over UDP/TCP/TLS (RFC 5425) ship straight from the endpoint. Snyk routes through its cloud (mandatory API token); the other OSS tools have nothing.

4. **Multi-registry lookalike detection.** Jaro-Winkler similarity (name + description) against four public registries (PulseMCP, Smithery, mcp.so, the official MCP registry), with an official-package allowlist and asymmetric scoring to cut false positives. Nobody else covers MCP typosquatting.

5. **Ed25519-signed compliance reports** (signing on by default, key sealed in the OS keychain, verifiable offline; the PDF footer carries the signature notice) with native mapping to SOC 2 (CC6.1/CC7.1/CC7.2), ISO 27001, OWASP MCP (MCP03/MCP09), SAFE-MCP (T1001/T1201), OWASP ASI (ASI06) and — where a technique is clearly applicable — MITRE ATT&CK / ATLAS (T1195, T1036, T1567, T1598, ATLAS AML.T0051). An auditor-grade, offline-verifiable artifact that neither the OSS scanners nor the gateways offer.

6. **Supply-chain attestation and version-level rug-pull.** For every npm-launched server (`npx`), Sentinel resolves the real package, then attests it against the public npm registry: SHA-512 tarball integrity, maintainers, publish date, weekly downloads, and whether the version is pinned. Re-attesting later flags a *version-level* rug-pull — the exact **Postmark** pattern, where a reputable package republishes a tampered artifact while the MCP tool surface is unchanged: same version + different SHA-512 is **critical**, a moved version is **high**. Lookalike scanning is also now **confusable-aware** (UTS#39 skeleton), catching homoglyph spoofs (e.g. Cyrillic `а` in `pаypal`) that plain Jaro-Winkler would miss.

7. **Offline CVE/OSV matching, cross-server shadowing and OAuth/SSRF checks (Vague D).** Sentinel ships an **embedded, offline CVE base** and matches each resolved package + version against it — mcp-remote (CVE-2025-6514), MCP Inspector (CVE-2025-49596), the filesystem server's "EscapeRoute" (CVE-2025-53109/53110) and the MCP Python SDK (CVE-2025-53365/53366) — with a strict anti-false-positive rule (a non-parseable or already-fixed version is never flagged). It is the only endpoint tool here that also detects **cross-server tool shadowing** (name collisions + cross-server poisoning, SAFE-T1102), diffs **project-config content** to catch the MCPoison config swap (CVE-2025-54136), and runs **static OAuth/SSRF checks** on HTTP servers (cloud-metadata SSRF CWE-918, confused deputy RFC 8707, token passthrough CWE-522) — all 100 % local.

---

## Where a competitor leads today — and the road past them

Honest gaps, with the plan to close each one:

1. ~~**Real-time runtime detection**~~ **Closed (June 2026), extended in Vague D.** The stdio proxy (`sentinel-scan::proxy`) inspects `tools/call` live — argument poisoning, streaming exfiltration combos (read-secret + external-write within a session) plus the 3-legged **lethal trifecta**, sampling/elicitation abuse — without ever persisting payload content. Vague D added a **runtime-output/error scan (ATPA)**: the `result`/`error` of each `tools/call` is inspected (correlated to its request by JSON-RPC id), catching poisoning that only surfaces at runtime, invisible to a static `tools/list` scan. Detection-only by default: bytes are relayed bit-exact.

2. ~~**Skills/agents coverage**~~ **Closed (June 2026).** Discovery now scans skills and sub-agents across user (`~/.claude/skills`, `~/.claude/agents`, `~/.agents/skills`, `~/.codex/skills`), project (`.claude/skills`, `.agents/skills` in every known Claude Code project) and extension (Claude Code plugins) scopes, and runs every artifact through the poisoning inspector.

3. ~~**Hybrid detection engines**~~ **Closed (June 2026), wired end to end.** The poisoning pipeline (`InspecteurPoisoning::inspecter_complet`) now runs, in order: regex patterns + Unicode anti-smuggling (zero-width, bidi controls, the Tags block, ANSI escapes) on the raw text, NFKC normalization to defeat full-width/homoglyph evasions, line-jumping patterns, then YARA rules (yara-x, pure Rust — 3 embedded rules + an importable rule directory), and finally an optional, off-by-default *local* LLM judge via Ollama. Zero-cloud preserved: localhost only, short timeouts, nothing leaves the machine. **Now exposed both in the CLI** (`sentinel scan` and the new `sentinel audit <path>`, with `--yara`/`--no-yara`/`--llm`/`--llm-url`) **and in the desktop app** (Settings → *Detection engines*: YARA toggle, local LLM-judge toggle + endpoint, read-only list of the embedded YARA rules).

4. **Enforcement / "approve before run"** (ToolHive: container isolation, per-tool policies, OIDC). **Largely closed in Vague D.** Two complementary controls now exist: (a) config-level enforcement still quarantines a compromised server from the client config (timestamped backup, one-click restore); and (b) the stdio proxy now has an inline **approve-before-run gate** — each `tools/call` is classified Low/Medium/High before relay, and with `enforce=true` a high-risk call (external write carrying a secret) is **held, never relayed**, raising an "awaiting approval" finding. *What's delivered vs. what remains:* the gate is **opt-in** (`ConfigProxy.enforce`, detection-only by default) and is a deterministic risk gate, not a full **interactive UI approval flow** — there is no operator pop-up yet that pauses the call and resumes it on click, and the gate is wired in the proxy/library rather than surfaced as a CLI flag or desktop toggle. *Roadmap:* expose the enforce toggle in the CLI/desktop and add the interactive operator prompt. Sentinel still does not do container isolation or OIDC per-tool policies (ToolHive's model).

5. **Traction and distribution** (2,552 stars for Snyk's scanner, Smithery registry integration, 961 for Cisco). Threat-intel matching also still relies on a curated feed (bundled in the binary + optional 24 h refresh from a configured URL) rather than a continuously-synced live registry of known-malicious packages. *Roadmap:* open-source the scan engine (open-core model), a live registry integration, and public benchmarks ("we scanned N public servers").

---

## Positioning, head to head

> **The only EDR for MCP servers that speaks your SOC's language — 100 % local, zero cloud.**

**vs Snyk / mcp-scan** — They ship your configs to their cloud with a mandatory token; Sentinel analyzes everything locally, in Rust, signed and notarized. Sovereignty, latency, confidentiality.

**vs ToolHive** — ToolHive secures the servers you install *through it*; Sentinel finds the 14 clients and the shadow servers your developers have *already* installed. Discovery vs management.

**vs one-shot scanners (mcp-watch, mcp-shield, Cisco)** — A point-in-time scan misses tomorrow's rug-pull; Sentinel keeps persistent baselines and alerts your SIEM at the first byte that changes.

**vs commercial platforms (Proofpoint, JFrog, Wiz, Qualys, Prisma AIRS)** — They see the cloud; Sentinel sees the workstation — where Claude Desktop, Cursor and their MCP servers actually live. Sentinel is the "shadow MCP endpoint" brick that complements their network visibility, with STIX/TAXII to integrate into their ecosystem rather than fight it.

---

## Sources

- [snyk/agent-scan (formerly mcp-scan)](https://github.com/invariantlabs-ai/mcp-scan)
- [Introducing MCP-Scan — Invariant Labs](https://invariantlabs.ai/blog/introducing-mcp-scan)
- [MCP-Scan Review 2026 — AppSec Santa](https://appsecsanta.com/mcp-scan)
- [stacklok/toolhive](https://github.com/stacklok/toolhive)
- [ToolHive Docs — Stacklok](https://docs.stacklok.com/toolhive/)
- [kapilduraphe/mcp-watch](https://github.com/kapilduraphe/mcp-watch)
- [eqtylab/mcp-guardian](https://github.com/eqtylab/mcp-guardian)
- [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)
- [riseandignite/mcp-shield](https://github.com/riseandignite/mcp-shield)
- [Smithery x Invariant partnership](https://invariantlabs.ai/blog/smithery-mcp-scan)
- [AgentSeal — 1,808 servers scanned, 66 % with findings](https://agentseal.org/blog/mcp-server-security-findings)
- [JFrog AI Catalog — Shadow AI & MCP governance](https://jfrog.com/blog/jfrog-ai-catalog-evolves-to-detect-shadow-ai-govern-mcps/)
- [Proofpoint MCP Security Platform](https://www.proofpoint.com/us/products/ai-mcp-security)
- [Qualys TotalAI — MCP Shadow IT](https://blog.qualys.com/product-tech/2026/03/19/mcp-servers-shadow-it-ai-qualys-totalai-2026)
- [Prisma AIRS 3.0 — Palo Alto](https://www.paloaltonetworks.com/blog/2026/03/prisma-airs-3-0-autonomous-ai/)
- [Wiz AI Security](https://www.wiz.io/)
- [MCP Vulnerability Scanner: Pre-Deploy vs Runtime — PipeLab](https://pipelab.org/learn/mcp-vulnerability-scanner/)
- [The State of MCP Security 2026 — PipeLab](https://pipelab.org/blog/state-of-mcp-security-2026/)
- [Best MCP Security Tools 2026 — MCP Manager](https://mcpmanager.ai/blog/mcp-security-tools/)

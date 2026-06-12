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
| Continuous runtime detection | **Real-time stdio proxy (poisoning, exfil combos, sampling abuse) + periodic scan + file watcher** | Real-time proxy mode | Yes (gateway, OIDC, per-tool policies) | No | Yes (live approvals) | No | Yes (traffic) |
| Tool poisoning | **40+ patterns + YARA rules + optional local LLM judge (Ollama), all local** | Yes (cloud LLM, Snyk token required) | Indirect | Yes | Basic checks | Yes (YARA + LLM-judge) | Yes |
| Lookalikes / typosquatting | **Jaro-Winkler, 4 registries** | No | No | No | No | No | Partial (JFrog) |
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

5. **Ed25519-signed compliance reports** with native mapping to SOC 2 (CC6.1/CC7.1/CC7.2), ISO 27001, OWASP MCP (MCP03/MCP09) and SAFE-MCP (T1001/T1201). An auditor-grade, offline-verifiable artifact that neither the OSS scanners nor the gateways offer.

---

## Where a competitor leads today — and the road past them

Honest gaps, with the plan to close each one:

1. ~~**Real-time runtime detection**~~ **Closed (June 2026).** The stdio proxy (`sentinel-scan::proxy`) now inspects `tools/call` live — argument poisoning, streaming exfiltration combos (read-secret + external-write within a session), sampling/elicitation abuse — without ever persisting payload content. Detection-only: bytes are relayed bit-exact; blocking remains the guard's job.

2. ~~**Skills/agents coverage**~~ **Closed (June 2026).** Discovery now scans skills and sub-agents across user (`~/.claude/skills`, `~/.claude/agents`, `~/.agents/skills`, `~/.codex/skills`), project (`.claude/skills`, `.agents/skills` in every known Claude Code project) and extension (Claude Code plugins) scopes, and runs every artifact through the poisoning inspector.

3. **Enforcement/blocking** (ToolHive: container isolation, per-tool policies, OIDC). Sentinel detects first, blocks second: enforcement mode already quarantines a compromised server from the client config (timestamped backup, one-click restore) but is opt-in and advisory by default. *Roadmap:* an "approve before run" gate.

4. ~~**Hybrid detection engines**~~ **Closed (June 2026).** YARA rules (yara-x, pure Rust — 3 embedded rules + importable rule directory) plus an optional, off-by-default *local* LLM judge via Ollama. Zero-cloud preserved: localhost only, short timeouts, nothing leaves the machine. UI/CLI exposure on the way.

5. **Traction and distribution** (2,552 stars for Snyk's scanner, Smithery registry integration, 961 for Cisco). *Roadmap:* open-source the scan engine (open-core model), pursue a registry integration, publish public benchmarks ("we scanned N public servers").

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

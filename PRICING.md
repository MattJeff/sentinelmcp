# Pricing & Licensing — open-core

> **The local tool is free and open-source (MIT), forever — including SIEM, STIX/TAXII and signed
> reports.** We don't gate detection. The paid layer is the **team / managed / hosted** surface built
> *on top* — collaboration, fleet, SSO, support — never a paywall on what already ships open.
>
> Model: **open-core**, build a company. (This also keeps full acquisition optionality — an open-core
> business with revenue is *more* acquirable, not less.)

---

## The rule we won't break

**Nothing that is open today ever gets taken behind a paywall.** SIEM connectors, STIX/TAXII, Ed25519
signed reports, every detector — all MIT, all free, all permanent. Retroactively gating open code burns
trust (and you can't relicense what's already MIT anyway). The paid tier must be *new* value for *teams*,
not a tax on individuals.

---

## Free & open — **the whole local tool, forever (MIT)**

Everything a developer or a single machine/CI needs. No account, no telemetry, no limits.

| Capability | |
|---|---|
| Discovery across 14 AI clients + canonical SHA-256 fingerprints + drift / rug-pull detection | ✅ Free & open |
| Tool poisoning (40+ patterns + Unicode anti-smuggling + line-jumping + YARA + optional **local** LLM judge) | ✅ Free & open |
| Lookalikes/confusables, lethal-trifecta, supply-chain rug-pull, offline CVE, skills scanning | ✅ Free & open |
| Real-time stdio proxy (tool-output scanning, approve-before-run) | ✅ Free & open |
| `sentinel audit` + **GitHub Action**, desktop app + CLI (macOS/Linux/Windows) | ✅ Free & open |
| **SIEM** (Splunk/Elastic/Syslog TLS), **STIX 2.1 / TAXII 2.1**, **Ed25519-signed compliance reports** | ✅ Free & open |
| `sentinel benchmark`, `sentinel report`, Prometheus `/metrics` | ✅ Free & open |

> A single SOC engineer can wire Sentinel into Splunk and ship signed reports **for free, forever.**
> That's the adoption engine — we don't touch it.

---

## Paid — **the team & managed layer** (new value, built on top)

These do **not** exist in the local tool today; they're net-new, multi-user/org-scale capabilities.
Source-available (not MIT) so the company is fundable, but never gating the open core.

### Team — *~$19 / dev / month (annual)* or *$249 / month flat, ≤15 devs*
*Targets Maya, Head of AppSec — below Snyk (~$25/dev), Socket (~$25–50/dev).*

- **Cross-machine, shared canonical baselines** — approve once, enforce across the whole team/fleet.
- **Team policies & allow/deny lists** — centrally managed, versioned.
- **Drift history & audit trail** — who approved what, when, why (org-wide, retained).
- **Fleet dashboard** — every developer machine + CI in one view, by colour/severity.
- **SSO, RBAC, team alerting** (Slack/webhook routing, on-call).

### Enterprise — *contact us*

- **Managed / hosted control plane** (optional, opt-in) — for teams who don't want to self-host the
  team layer.
- **SAML / SCIM, advanced RBAC, data residency, retention controls.**
- **Curated threat-intel feed & rule updates** (managed subscription — the *feed*, not the engine).
- **SLAs, priority support, deployment & onboarding.**

> Running Sentinel across a team and want the fleet/managed layer? Open an issue titled `enterprise`
> or contact the maintainer. *(See `LAUNCH.md` for the design-partner program.)*

---

## Launch timing — **don't gate anything in week 1**

Open-core *structure*, adoption-first *sequencing*:

1. **Launch: 100% free & open.** Win stars, installs, and 3–5 design partners.
2. **Validate willingness to pay** with those design partners (the Team features above).
3. **Then** ship the Team tier. The pricing page exists from day one (signals seriousness) but **nothing
   is gated until there's pull.** Premature monetization kills the traction that creates all the value.

---

## Licensing & IP

| Layer | License | Why |
|---|---|---|
| The whole current tool (core) | **MIT** | Max adoption & trust; auditable security tool; permanent. |
| New Team/Enterprise layer | **Source-available (e.g. BSL 1.1 → converts to Apache/MIT after N years)** | Fundable company without closing the core; converts to open over time. |
| Contributions | **DCO sign-off** (`git commit -s`) | Clean, relicensable provenance — what every acquirer's due diligence checks. |

- No surprise relicensing of MIT code.
- DCO (not a heavy CLA) keeps contribution friction near zero.

---

## Why open-core is the right call here

- **Sustainable**: real revenue from the team/managed layer funds the open core indefinitely.
- **Trust-preserving**: the security-critical detection stays open and auditable — the only credible
  posture for a security tool.
- **Acquisition-compatible**: open-core with revenue + adoption + clean IP is the *strongest* acquisition
  profile (Snyk/Wiz/Cisco/Palo Alto buy adoption *and* a monetizable surface). Precedent: Invariant→Snyk.
- **Honest**: individuals never pay for what they have today; teams pay for genuinely new value.

**Bottom line:** free, open, auditable local tool forever → paid team/managed layer on top → revenue funds
the core and keeps every exit open.

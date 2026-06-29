# Sentinel MCP — Launch Kit (7-day plan)

> Plan de distribution ultra-rapide pour **Sentinel MCP** (« the EDR for MCP servers »).
> Issu d'un panel d'experts (lancement, growth dev, marché sécu, GTM/sales, contenu/social, partenariats).
>
> ⚠️ **Règle d'or — honnêteté.** Pour un outil de **sécurité**, une statistique inventée ou une sur-promesse
> est fatale. **Vérifie chaque chiffre/incident avant publication.** Privilégie tes **propres chiffres**
> issus de `sentinel benchmark` (« we scanned N public MCP servers, X% had findings ») — c'est exactement
> pour ça qu'on l'a codé. Reste fidèle aux gaps documentés (`docs/COMPARISON.md`).

---

## ⭐ Les 5 actions à plus fort levier de la semaine

1. **README = landing page.** Tout le trafic atterrit là : hero + GIF démo + tableau comparatif + install 1 ligne.
2. **Show HN** mardi-jeudi ~8-9 h ET, titre **sans adjectifs** + 1er commentaire « maker » posté immédiatement.
3. **`sentinel benchmark` public** → un chiffre choc **réel** qui alimente le thread X et le post de blog.
4. **GitHub Action sur le Marketplace** (`fail-on: high`) — adoption bottom-up en CI, le canal le plus collant.
5. **Wedge de positionnement** : *« l'EDR MCP local et open — le scanner que Snyk a racheté et fermé,
   reconstruit pour rester gratuit, tourner chez toi, et parler Splunk/STIX d'office. »*

---

## 🗓️ Calendrier J0 → J7

### J0 — Préparation (ne rien publier)
- [ ] **README hero** (voir `README.md`, déjà mis à jour par ce kit) + relire la promesse / les gaps honnêtes.
- [ ] **GIF démo 15–25 s** de `sentinel scan` (outils : [VHS](https://github.com/charmbracelet/vhs), asciinema, terminalizer). Montrer la découverte multi-clients + un constat rouge.
- [ ] **Landing GitHub Pages** (voir `landing/index.html`).
- [ ] **Figer le chiffre benchmark** : `sentinel benchmark --json > benchmark.json` (ou `--offline`), noter `N serveurs / X% avec findings`.
- [ ] **Réserver les namespaces** (voir § Namespaces) : crates.io, npm, `homebrew-sentinel`, `sentinel-action`.
- [ ] **Release multi-OS** via `cargo-dist` (voir `packaging/cargo-dist.md`) → binaires + checksums + formules.
- [ ] **Verrouiller toute la copie** de lancement dans un doc (titres, threads, FAQ objections).

### J1 (lun) — Repo prêt pour le pic
- [ ] Topics GitHub : `mcp`, `mcp-security`, `edr`, `model-context-protocol`, `rust`, `devsecops`, `supply-chain-security`, `ai-security`. Description courte = la tagline.
- [ ] Badges à jour (release, CI, license, platform, crates.io).
- [ ] **Homebrew tap** : créer `MattJeff/homebrew-sentinel`, pousser `packaging/homebrew/sentinel.rb`, tester `brew install MattJeff/sentinel/sentinel`.
- [ ] **Liste de 40 leads AppSec/DevSecOps** (LinkedIn Sales Navigator, scale-ups AI-forward) pour le J5.

### J2 (mar) — Lancement principal
- [ ] **SHOW HN** ~8–9 h ET (mar-jeu), titre verbatim + **1er commentaire maker posté <5 min**.
- [ ] **Thread X « Lethal Trifecta »** (asset ci-dessous).
- [ ] `cargo publish` (crates.io) + **wrapper npm** (`npx sentinelmcp scan`, zéro postinstall via cargo-dist).
- [ ] Page **Product Hunt « Coming Soon »** (collecte de notify-list).

### J3 (mer) — Substance technique
- [ ] **Blog technique (Dev.to + cross-post)** : *« How we fingerprint every MCP server your laptop exposes with canonical SHA-256 to catch rug-pulls »*.
- [ ] **PR aux awesome-lists** : `Puliczek/awesome-mcp-security`, `punkpeye/awesome-mcp-servers`, `wong2/awesome-mcp-servers`/mcpservers.org.
- [ ] **Publier la GitHub Action** (voir § Marketplace).

### J4 (jeu) — Communautés
- [ ] **r/netsec + r/mcp** : writeup **technique** (pas un pitch).
- [ ] **Forum Anthropic + Discord MCP** (#showcase) : message du champion.
- [ ] **Cold emails newsletters** : tl;dr sec (Clint Gibler), AI Security Newsletter (Tal Eliyahu), Adversa.

### J5 (ven) — Design partners + monétisation
- [ ] **40 cold DM/emails** design-partners (objectif : 5–8 calls de 20 min). Templates ci-dessous.
- [ ] **Page pricing 3 tiers** (Local gratuit / Team / Enterprise).

### J6–J7 (week-end) — Amplification
- [ ] **Product Hunt** si momentum (souvent meilleur le mardi suivant).
- [ ] **Soumission aux annuaires MCP** (en tant qu'**outil de sécurité**, pas serveur) : Smithery, PulseMCP, mcp.so — voir `packaging/mcp-registry/SUBMISSION.md`.
- [ ] **Répondre à TOUT** (HN/Reddit/PH) dans l'heure. Récap métriques + relances.

---

## 📋 Pack d'assets prêts à copier

### Taglines (A/B)
1. `The EDR for MCP servers. 100% local.`
2. `Catch a malicious MCP server before your AI agent does.`
3. `MCP Detection & Response (MCPDR) — local, read-only, Rust.`

### Show HN — titre (sans adjectifs, verbatim)
```
Show HN: Sentinel – a local, read-only EDR for MCP servers (Rust, zero cloud)
```

### Show HN — 1er commentaire « maker » (poster <5 min après)
> Hi HN — I built Sentinel because I had ~30 MCP servers wired into Claude Code, Cursor and VS Code
> across my laptop and CI, and zero idea which ones could read my SSH keys or silently change their
> tool descriptions overnight (a "rug-pull").
>
> Sentinel is a single Rust binary. 100% local, read-only by default, no cloud, no telemetry. It
> discovers MCP servers across 14 agent clients, takes a canonical SHA-256 fingerprint of each, and
> diffs it every run — so a rug-pull or a typosquat lookalike trips an alert. Detection = 40+
> tool-poisoning patterns + Unicode smuggling + line-jumping + YARA + an optional **local** LLM judge
> (Ollama). It also speaks SOC (Splunk/Elastic, STIX/TAXII) and ships Ed25519-signed compliance reports.
>
> Free & open for local use. Feedback very welcome — especially on false positives.

### Thread X — hook « Lethal Trifecta »
> 1/ The "lethal trifecta" (private data + untrusted content + an exfil path) is why your AI agent is
> one poisoned tool away from leaking your keys. Here's how to see your own exposure in 60s, fully
> offline. 🧵
>
> 2/ MCP made this worse: Claude Code, Cursor, Windsurf etc. let agents connect to servers that can
> read your files AND call the internet. Most devs can't even list what they've connected.
>
> 3/ Sentinel (open, 100% local, Rust): `brew install MattJeff/sentinel/sentinel && sentinel scan` →
> every MCP server across 14 clients, fingerprinted, drift-watched. [GIF]

### Cold DM LinkedIn (design partner)
> Hi {First} — saw {Company}'s engineers run Cursor/Claude Code. Do you have an inventory of which MCP
> servers those agents can call, and an alert if one changes its tool definition overnight? We built
> Sentinel — a local, read-only EDR for MCP (the open alternative to the mcp-scan tool Snyk just
> acquired & closed). Looking for 5 design partners this month: free, ~1 month, two 30-min calls, you
> keep the tool. Worth a 20-min look?

### Cold email newsletters
> **Subject:** Local-first EDR for MCP servers (open source, maps to OWASP MCP Top 10)
>
> Hi {name} — love your MCP-security coverage. I shipped **Sentinel MCP**, an open-source, 100% LOCAL
> EDR for MCP servers (Rust). It discovers servers across 14 clients, takes a canonical SHA-256
> fingerprint, and detects tool poisoning (40+ patterns + Unicode smuggling + line-jumping + optional
> local LLM judge), rug-pulls, typosquats, CVEs and lethal-trifecta exfil combos. For SOC teams it
> speaks Splunk/Elastic, STIX/TAXII and ships Ed25519-signed compliance reports. Repo:
> https://github.com/MattJeff/sentinelmcp — happy to give you a 1-line blurb if useful.

### Pricing — 3 tiers
| Tier | Prix | Inclus |
|---|---|---|
| **Local** | Gratuit (MIT) | Découverte 14 clients, empreintes SHA-256 + drift, 40+ patterns + smuggling/line-jumping + YARA, lethal-trifecta + CVE, approve-before-run, desktop + CLI + GitHub Action. 1 machine, sans compte, sans télémétrie. |
| **Team** | ~19 $/dev/mo (annuel) | Baselines partagées, policies & allow/deny, historique de drift, alertes Slack/webhook, SSO. *(Sous Snyk ~25 $/dev, Socket ~25–50 $/dev.)* |
| **Enterprise** | Sur devis | SIEM (Splunk/Elastic/Syslog TLS), STIX/TAXII, rapports signés, support, déploiement. |

---

## 🚚 Canaux de distribution (ordre de priorité)

1. **GitHub Action Marketplace** (collant, CI) — voir § Marketplace.
2. **Homebrew tap** — `packaging/homebrew/sentinel.rb`.
3. **crates.io** (`cargo install sentinel-cli`) + **npm wrapper** (`npx sentinelmcp`) — voir `packaging/cargo-dist.md`.
4. **Registres MCP** — Smithery / PulseMCP / mcp.so + `packaging/mcp-registry/SUBMISSION.md`.
5. **awesome-lists** — PRs ciblées.

### Namespaces à réserver (J0)
| Canal | Nom | Comment |
|---|---|---|
| crates.io | `sentinel-cli` (déjà nommé) | `cargo publish` (vérifier email + Trusted Publishing OIDC). |
| npm | `sentinelmcp` | `npm publish` du wrapper (cargo-dist). |
| Homebrew | `MattJeff/homebrew-sentinel` | repo tap dédié. |
| GitHub Action | `MattJeff/sentinel-action` (Marketplace) | repo dédié avec `action.yml` à la racine (copie de `action/action.yml`). |

### Marketplace (GitHub Action)
L'action existe déjà et est complète : [`action/action.yml`](action/action.yml) (composite ; installe le CLI depuis les Releases, exécute `sentinel audit --json`, publie Job Summary + annotations, `fail-on`).

- **Usage immédiat** (sans Marketplace) :
  ```yaml
  - uses: MattJeff/sentinelmcp/action@v1
    with: { path: '.', fail-on: 'high' }
  ```
- **Publication Marketplace** : GitHub exige `action.yml` à la **racine** d'un repo. Crée `MattJeff/sentinel-action`,
  copies-y `action/action.yml` + `action/README.md`, tague `v1`, puis « Publish this Action to the Marketplace ».

---

## 📊 KPIs & garde-fous

- **Mesurer** : stars/jour, installs (brew/npm/`cargo install`/Action runs), position front-page HN/PH, calls design-partners bookés, trafic landing.
- **Garde-fou #1** : ne publier **aucune** stat non vérifiée. Utiliser les chiffres `sentinel benchmark` réels.
- **Garde-fou #2** : répondre vite et avec humilité aux faux positifs signalés (un EDR crédible assume ses limites).
- **Risque produit** : la CI GitHub Actions est actuellement bloquée par la facturation du compte — la régler avant le pic de trafic (les visiteurs cliquent le badge CI).

---

*Ce kit est généré à partir d'un panel d'experts web. Adapte les exemples, vérifie tout chiffre, et garde le ton factuel propre à un produit de sécurité.*

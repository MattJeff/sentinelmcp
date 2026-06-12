# Sentinel MCP — Révolution 2026

Rapport issu du workflow multi-agents du 2026-06-11 : 7 lentilles d'idéation (recherche web), 30 idées brutes, 24 retenues après déduplication, notées par 3 juges indépendants (faisabilité solo-dev / différenciation radicale / marché), specs détaillées du top 3, et 3 quick wins **déjà implémentés** dans des worktrees git avec revue adversariale.

---

## 1. Résumé exécutif

La thèse : Sentinel doit cesser d'être « un scanner MCP de plus » et occuper trois positions que personne n'a en 2026 :

1. **L'endpoint, pas le cloud.** Tous les concurrents sérieux (Snyk, Proofpoint, Wiz, Prisma AIRS) sont côté cloud/réseau. La position de Sentinel — dans le chemin stdio, sur le poste — est la seule d'où l'on peut inventorier la flotte d'agents, enregistrer des preuves inviolables et couper un serveur en moins d'une seconde.
2. **L'autorité technique, pas le produit.** Publier la recette d'empreinte (MCP-FP) pendant que SEP-1766 est encore ouvert transforme un détail d'implémentation en standard d'écosystème — le coup « Let's Encrypt publie ACME ».
3. **L'agent entier, pas seulement ses outils.** La surface d'attaque 2026 c'est les outils (MCP) **et** les instructions (skills, AGENTS.md) **et** la flotte (qui tourne, lancé par qui). Couvrir les trois fait de Sentinel le seul vrai « EDR pour agents IA ».

Le différenciateur transversal reste l'ADN existant : 100 % local, zéro cloud, signé Ed25519, vérifiable hors ligne.

---

## 2. Classement complet (24 idées, moyenne sur 3 juges /10)

| Rang | Id | Idée | Effort | Moyenne |
|---|---|---|---|---|
| 1 | 20 | **Agent Census** : inventaire local de la flotte d'agents (pas seulement des serveurs MCP) | moyen | **7,50** |
| 2 | 22 | **Boîte noire EU AI Act** : enregistrement inviolable des sessions agent + pack de preuves Art. 12/19 | moyen | **7,50** |
| 3 | 24 | **Kill-switch de flotte** : disjoncteur comportemental local + politique de quarantaine signée distribuable | moyen | **7,33** |
| 4 | 1 | **MCP-FP** : spécification ouverte d'empreinte canonique + crate de référence + SEP officiel | quick-win ✅ | 7,17 |
| 5 | 5 | MCP Trust Policy : allowlist organisationnelle signée, appliquée par le guard sur les 14 clients | moyen | 7,17 |
| 6 | 21 | **Skill-scan** : détection de skills empoisonnées (SKILL.md, AGENTS.md, ClawHub) | quick-win ✅ | 7,17 |
| 7 | 9 | Profil comportemental Markov des séquences d'appels dans le guard | moyen | 6,67 |
| 8 | 11 | MCP Malware Index + advisories MCPSA au format OSV | moyen | 6,67 |
| 9 | 18 | « Pwned Fingerprints » — API de réputation k-anonyme + filtre de Bloom hors ligne (modèle HIBP) | moyen | 6,67 |
| 10 | 19 | Détection de campagne par quorum — balises de dérive anonymes opt-in, publiées en STIX/TAXII | moyen | 6,50 |
| 11 | 2 | Sentinel Transparency Log + registre public de golden baselines (le crt.sh des serveurs MCP) | gros-chantier | 6,33 |
| 12 | 4 | Badge « Sentinel Verified » lié au digest exact, signé Ed25519, vérifiable hors ligne | moyen | 6,33 |
| 13 | 16 | **Sentinel servi en serveur MCP** : l'agent qui audite ses propres outils (/vet) | quick-win ✅ | 6,33 |
| 14 | 3 | `sentinel attest` : manifeste signé + attestation de build pour les auteurs de serveurs | moyen | 6,17 |
| 15 | 12 | Pack « attestation assurance cyber » : rapport signé comme preuve de contrôle IA pour assureurs | quick-win | 6,17 |
| 16 | 6 | Moteur d'embeddings 100 % local (candle + BERT quantisé) contre le poisoning paraphrasé | moyen | 6,00 |
| 17 | 10 | Détection sémantique du cross-server shadowing | moyen | 6,00 |
| 18 | 15 | Pare-feu pré-installation : interception deeplinks cursor:// claude:// et mcp.json plantés | gros-chantier | 6,00 |
| 19 | 13 | Open-core radical AGPL + licence commerciale OEM (guard embarqué dans les clients IA) | gros-chantier | 5,67 |
| 20 | 14 | `sentinel demo` — théâtre d'attaque en direct (rug-pull tué en temps réel) | quick-win | 5,67 |
| 21 | 8 | Dérive sémantique des baselines (rug-pull « à petits pas » par distance cosinus) | quick-win | 5,33 |
| 22 | 17 | sentinel-trust : web-of-trust décentralisé d'attestations (le cargo-vet des serveurs MCP) | gros-chantier | 5,17 |
| 23 | 23 | Passeport d'agent : attestation SPIFFE-like locale + AgentBOM CycloneDX | gros-chantier | 5,17 |
| 24 | 7 | Juge local de descriptions : Llama Prompt Guard 2 (86M) porté via candle | gros-chantier | 4,83 |

✅ = implémenté pendant ce workflow (voir §4). Note : la lentille « menaces offensives » a échoué en cours de route (sortie non structurée) — les 24 idées proviennent des 6 autres lentilles ; une relance ciblée de cette lentille reste pertinente.

---

## 3. Top 3 — specs détaillées

### 3.1 Agent Census — `sentinel fleet` (7,50)

**Vision.** Répondre à LA question CISO 2026 : « combien d'agents tournent chez nous, lancés par qui, avec accès à quoi ? » — depuis l'endpoint, là où personne ne regarde. Graphe agent→skills→serveurs MCP→credentials, propriétaire (UID), date d'apparition, et statut **shadow agent** pour tout agent absent d'un manifeste d'équipe versionné en git (`sentinel-fleet.toml`). L'anti-Agent 365, endpoint-first, zéro cloud.

**Architecture.** Module `fleet/` dans `sentinel-discovery` (réutilise ~60 % de l'existant : ContexteOs, les 14 sources, sysinfo déjà en dépendance, trust_graph, store, monitor, sinks SIEM) :
- `model.rs` : `AgentDecouvert` (types : CliInteractif, RoutinePlanifiee, SousAgent, Skill, Hook, ProcessusActif…), valeurs d'env jamais persistées (clés seules).
- Sources : promotion des clients découverts ; assets Claude (`~/.claude/skills`, agents, hooks) ; routines (launchd/crontab+systemd/schtasks XML) ; processus (implémente enfin le stub `runtime_inspector.rs` via sysinfo) ; OpenClaw/gateways.
- `manifeste.rs` : TOML versionnable git, `fleet init` pour bootstraper sans bruit jour 1 ; tout agent non déclaré ⇒ Shadow.
- Persistance V6 (`agents`, `agent_liens`) + GC ; CLI `sentinel fleet [--json|--csv|--graph]`, exit 1 si shadow ; constat `AgentFantome` → pipeline SIEM existant.

**Estimation.** ~18 jours-homme en 13 étapes (la plus grosse : routines multi-OS, 3 j). **Risque n°1** : parsing Task Scheduler Windows (passer par `/query /xml`, pas le CSV localisé) et faux positifs de la table de signatures de processus.

### 3.2 Boîte noire EU AI Act — flight recorder hash-chaîné (7,50)

**Vision.** Le wrapper stdio existant devient un enregistreur de vol inviolable : chaque tool call = une entrée d'un journal append-only hash-chaîné (SHA-256 de l'entrée précédente), scellé périodiquement par Ed25519 (graine en keychain OS), horodatage RFC 3161 optionnel. `sentinel evidence --format pdf` produit un pack de preuves mappé Art. 12 (record-keeping), 19 (conservation), 26 (déployeur), vérifiable hors ligne par un auditeur via `sentinel verify-log`. Vs Vorlon (SaaS) : la preuve ne quitte jamais le poste.

**Architecture.** Nouveau crate `sentinel-blackbox` : base SQLite séparée (`blackbox.db`, préserve l'invariant « aucun contenu tools/call dans sentinel.db ») ; 4 niveaux de rédaction (défaut `metadonnees` : aucun contenu, seulement hashes) ; scellements toutes les N entrées/T minutes ; rotation par segments trimestriels scellés avec purge 6/24 mois qui conserve la preuve d'existence ; côté guard, canal mpsc + writer dédié — **l'append ne bloque jamais le relais**, les trous deviennent des entrées `lacune_detectee` chaînées.

**Estimation.** ~16,5 jours-homme en 8 étapes ; MVP démontrable dès l'étape 4a (~8 j : session enregistrée, scellée, vérifiée hors ligne). Quasi zéro dépendance nouvelle (sha2, ed25519-dalek, rusqlite, keyring, printpdf déjà dans le workspace).

### 3.3 Kill-switch de flotte — `sentinel panic` + disjoncteur (7,33)

**Vision.** Transformer la position d'observation (le guard vit dans le chemin stdio) en position de **réponse** — le « R » de MCPDR. Trois étages : (1) disjoncteur comportemental à fenêtre glissante dans le wrapper (quarantaine <1 s d'un serveur qui déraille : rafale destructive, exfiltration de volume, sortie de scope) ; (2) `sentinel panic` — bouton rouge qui tue tous les processus MCP et neutralise les configs de façon réversible (`--dry-run`, `--restore`) ; (3) politique de flotte TOML signée Ed25519, version monotone anti-rejeu, distribuable par git/MDM sans serveur central.

**Architecture.** Nouveau crate `sentinel-response` (politique.rs, disjoncteur.rs à horloge injectable, actions.rs kill cross-platform + neutralisation configs, boite_noire.rs JSONL hash-chaîné). Guard : inspection bornée des tools/call, substitution JSON-RPC -32001 « server quarantined », check quarantaine **au démarrage** (casse la boucle « le client relance le serveur tué »). Fail-open sur erreur d'analyse, fail-closed sur quarantaine/bannissement. Migration V6 (quarantaines, politique_active), `TypeConstat::Quarantaine` → pipeline d'alertes existant.

**Estimation.** 10 étapes. **Risque produit n°1** : faux positifs du disjoncteur (quarantaine intempestive = confiance détruite). Mitigation : observe-only par défaut (`--enforce` opt-in, comme `--block` aujourd'hui), seuils en ratios plutôt qu'en volumes, allowlist par serveur, levée en un clic.

---

## 4. Quick wins implémentés (3 worktrees, rien de committé)

| Quick win | Worktree | Build | Tests | Revue |
|---|---|---|---|---|
| MCP-FP (crate `mcp-fingerprint` + SPEC.md) | `.claude/worktrees/wf_9550cbda-f6d-15` | ✅ | ✅ (118 passed) | ✅ OK — issues mineures |
| Skill-scan (`sentinel skills`) | `.claude/worktrees/wf_9550cbda-f6d-16` | ✅ | ✅ (~40 verts) | ⚠️ OK avec réserves |
| Serveur MCP (`sentinel serve-mcp` + /vet) | `.claude/worktrees/wf_9550cbda-f6d-17` | ✅ | ✅ (38 verts, dont e2e stdio) | ✅ OK — corrections doc |

### 4.1 MCP-FP — `mcp-fingerprint` (id 1, moy. 7,17)

Crate Rust autonome extrait de sentinel-detect (Apache-2.0, deps minimales, wasm-ready), SPEC.md style RFC arrimée à **SEP-1766**, 7 vecteurs de test normatifs (hashes revérifiés indépendamment en Python par le relecteur), sentinel-detect refactoré en façade — **sortie identique octet à octet, baselines V5 intactes**. La revue confirme : portage fidèle ligne à ligne, aucun bug fonctionnel, build wasm OK.

À corriger avant publication : fichier LICENSE Apache-2.0 absent (et divergence avec le MIT du workspace) ; §3.5 de la spec sur-promet l'interop ECMAScript (1 vs 1.0 impossible à préserver via `JSON.parse`) ; ajouter un vecteur couvrant l'échappement `\u00XX`. **Action stratégique : soumettre le SEP au repo modelcontextprotocol pendant que la fenêtre est ouverte.**

### 4.2 Skill-scan — `sentinel skills` (id 21, moy. 7,17)

Nouveau module `sentinel-detect::skills` réutilisant les 40+ patterns + 7 patterns propres aux skills (curl|sh, ~/.aws, keychain, contexte dynamique — vecteur Datadog), sosies Jaro-Winkler (corpus 16 skills, seuil 0,92), baseline SHA-256 anti-rug-pull. Commande `sentinel skills` (codes 0/1/2), hook pre-commit, input GitHub Action. Preuve de demande la plus brûlante du lot : Snyk ToxicSkills — 36 % des 3 984 skills ClawHub avec injection, 76 voleurs de credentials confirmés.

Réserves de revue à corriger **avant merge** :
- **Haute** : `scan-skills=true` par défaut dans l'Action cassera la CI de tous les utilisateurs existants tant que la release CLI incluant `skills` n'est pas publiée (le binaire vient des releases). → défaut `false` ou détection de la sous-commande.
- **Moyenne** : faux positifs vérifiés — « debugger » flagué sosie de « debug » (0,925) : appliquer l'asymétrie des lookalikes MCP (commit c8b6f64) ; une mention documentaire de `~/.aws` produit 2 constats **critiques** : dégrader la sévérité sur la prose markdown.
- **Moyenne** : baseline rug-pull indexée par chemin tel-que-passé (relatif vs absolu) → `fs::canonicalize` avant insertion/lookup, + purge des skills supprimées.

### 4.3 Serveur MCP — `sentinel serve-mcp` (id 16, moy. 6,33)

Sentinel exposé en serveur MCP stdio (JSON-RPC ligne à ligne, **zéro dépendance ajoutée**) avec 4 outils : `vet_server` (score 0-100, verdict approuver/examiner/bloquer, fonctionne sur des paquets pas encore installés), `explain_finding`, `diff_baseline`, `guard_status`. Livré avec slash command Claude Code `/vet`, règle Cursor, one-liner `claude mcp add sentinel -- sentinel serve-mcp`. Test e2e qui pilote une vraie session MCP sur le binaire. « Le serveur MCP qui protège des serveurs MCP » — distribution gratuite par les registres eux-mêmes.

Réserves de revue : la doc /vet référence `explain_finding` par UUID mais aucun outil exposé ne retourne d'UUID (exposer les UUID dans scan --json ou reformuler) ; `diff_baseline` n'honore pas le matching par nom annoncé ; **compromis à assumer : `probe=true` par défaut exécute réellement le serveur audité** — court-circuiter le probe quand le verdict statique est déjà « bloquer ».

---

## 5. Feuille de route 2026 séquencée

1. **Maintenant (semaine 1-2)** — Finaliser et merger les 3 quick wins : corrections de revue (LICENSE + vecteur `\u00XX` pour MCP-FP ; asymétrie sosies + sévérité prose + canonicalisation pour skills ; doc UUID + probe-gating pour serve-mcp), puis release **v0.5** (débloque l'Action skills). Soumettre le **SEP MCP-FP** — c'est la fenêtre la plus périssable du lot.
2. **T3 2026** — **Kill-switch** (id 24) en mode observe-only d'abord : c'est l'extension naturelle du guard, et le disjoncteur + `panic` + politique signée font passer Sentinel de « Detection » à « Detection & Response » pour de vrai. L'étape 5 (runtime_inspector réel) est partagée avec l'Agent Census → la faire en premier.
3. **T3-T4 2026** — **Agent Census** (id 20) : réutilise le runtime_inspector du kill-switch ; `sentinel fleet` + manifeste git + constat AgentFantome. C'est l'argument de vente entreprise n°1.
4. **T4 2026** — **Boîte noire EU AI Act** (id 22) : les obligations high-risk s'appliquent à partir d'août 2026, le timing réglementaire est idéal ; MVP en ~8 jours, pack de preuves ensuite. Synergie : la boîte noire du kill-switch (boite_noire.rs) et celle-ci doivent partager le même module de chaîne de hachage.
5. **En continu** — Trust Policy (id 5, complément direct du kill-switch), Pwned Fingerprints / quorum STIX (ids 18-19, premier pas vers l'effet de réseau **sans** trahir le zéro-cloud), Markov guard (id 9, nourrit le disjoncteur).
6. **Relancer la lentille « menaces offensives »** (échouée pendant le workflow) pour alimenter le corpus d'attaques et les patterns.

Fil rouge : chaque brique réutilise la précédente (guard → disjoncteur → census → boîte noire), et tout reste signé, local, vérifiable hors ligne.

---

## 6. Risques et angles morts

- **Standard capturable** : MCP-FP publié en Apache-2.0 est réimplémentable par un acteur plus gros ; le fossé est l'autorité (citation dans le SEP) et la vitesse, pas la licence. D'où l'urgence de la soumission.
- **Faux positifs = poison de la confiance** : démontré expérimentalement sur skill-scan (« debugger »/« debug », `~/.aws` documentaire) et identifié comme risque n°1 du disjoncteur. Règle produit : tout mécanisme bloquant naît en observe-only.
- **Willingness to pay** : les juges marché notent que MCP-FP et serve-mcp sont des canaux d'autorité/distribution, pas du revenu. Le revenu est dans le trio entreprise : census + boîte noire + kill-switch (CISO, conformité, assurance).
- **Lentille menaces manquante** : le classement sous-représente les détections offensives de pointe (sleeper tools, abus sampling/elicitation, A2A) — à combler.
- **Dépendance aux releases** : deux quick wins (Action skills, distribution serve-mcp) ne sont utiles qu'après publication v0.5 — la release est le goulot.
- **Sécurité du probe** : `vet_server` exécute le serveur qu'il audite (env minimal, mais exécution quand même). À encadrer avant d'en faire l'argument viral.
- **Incident notable** : pendant la revue, une instruction injectée par un serveur MCP tiers (« Easter Egg » du serveur everything) est apparue dans une sortie d'outil et a été correctement ignorée — exactement la classe d'attaque que Sentinel détecte. En faire un cas de test du corpus.

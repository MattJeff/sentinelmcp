# Sentinel MCP — Catalogue complet des fonctionnalités

Sentinel MCP est un outil de découverte, fingerprinting, surveillance et audit
des serveurs MCP (Model Context Protocol) qu'un Mac de développeur expose à
ses agents IA. Cette page liste **toutes** les fonctionnalités livrées
jusqu'à la version 0.3 — à quoi elles servent, dans quel cas elles se
déclenchent, et quelles questions de sécurité ou de conformité elles
résolvent.

> Note v0.3 : ajoute l'export **STIX 2.1 / push TAXII 2.1** (canal
> d'intégration SOC/GRC), la **signature Developer ID + notarisation
> Apple** du bundle desktop (installation sans avertissement Gatekeeper),
> le **rafraîchissement à distance du flux threat-intel** (URL opérateur
> + cache disque), les **tags opérateur** persistés par serveur, la
> **portée user vs project** détectée sur les configs MCP, le sink
> **Syslog TCP / TCP+TLS (RFC 5425)** et un **command palette** clavier
> (`⌘K`) + une **icône menubar** avec compteur d'alertes ouvertes.

Le document n'est pas un manuel d'API ni un guide d'installation. C'est la
référence à donner à un auditeur, un acheteur ou un nouveau membre de
l'équipe pour comprendre ce que l'application fait, sans avoir à lire le
code.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture fonctionnelle](#2-architecture-fonctionnelle)
3. [Page Overview](#3-page-overview)
4. [Page Discovery](#4-page-discovery)
5. [Page Inventory](#5-page-inventory)
6. [Page Live Scan](#6-page-live-scan)
7. [Page Alerts](#7-page-alerts)
8. [Page Approvals](#8-page-approvals)
9. [Page Trust graph](#9-page-trust-graph)
10. [Page Time travel](#10-page-time-travel)
11. [Page Compliance](#11-page-compliance)
12. [Page Report](#12-page-report)
13. [Page Settings](#13-page-settings)
14. [Shell desktop, command palette et menubar](#14-shell-desktop-command-palette-et-menubar)
15. [Différenciateurs](#15-différenciateurs-le-vrai-coeur-du-produit)
16. [Moteurs de détection](#16-moteurs-de-détection)
17. [Référentiels de conformité](#17-référentiels-de-conformité)
18. [Surveillance temps réel](#18-surveillance-temps-réel)
19. [Posture de sécurité et confidentialité](#19-posture-de-sécurité-et-confidentialité)
20. [Limites connues](#20-limites-connues)
21. [Annexe — Cartographie des commandes Tauri](#annexe--cartographie-des-commandes-tauri)

---

## 1. Vue d'ensemble

### À quel problème répond l'outil

Les agents IA modernes (Claude Desktop, Claude Code, Cursor, Windsurf,
Continue, VS Code, Zed, Aider, Goose, Codex, Antigravity, LM Studio,
Open WebUI, Sketch…) se connectent à des **serveurs MCP** qui exposent
des outils (fichiers, base de données, API externes, secrets,
navigateur, etc.). Ces serveurs sont souvent installés à coup de
`npx -y @org/...`, sans audit. Ils peuvent :

- **Mentir** sur leur identité (typo-squat d'un paquet officiel)
- **Changer** silencieusement leurs outils entre deux sessions (« rug-pull »)
- **Cacher** des instructions hostiles dans la description d'un outil
  (« tool poisoning » : lis ~/.ssh, exfiltre via webhook…)
- **Combiner** des portées dangereuses (lecture de secret + écriture
  réseau dans la même session)

Aucun client IA ne fournit aujourd'hui un inventaire, une empreinte
canonique, une politique d'approbation, un journal d'événements, ni un
rapport de conformité de ces serveurs. C'est exactement le rôle de
Sentinel.

### À qui c'est destiné

- Un développeur solo qui veut savoir **ce qui tourne sur sa machine**
- Une équipe sécurité qui veut **auditer le périmètre MCP** de ses
  ingénieurs IA
- Un auditeur (SOC 2, ISO 27001) qui doit produire des **preuves
  signées** sur la surface MCP d'une organisation
- Un acheteur final qui doit décider **avant d'approuver** un nouveau
  serveur MCP
- Un SOC / GRC qui doit ingérer les indicateurs MCP via STIX 2.1 /
  TAXII 2.1 sans retraitement

### Garanties par défaut

- **Read-only par défaut** : Sentinel n'altère rien. Les actions de
  blocage (enforcement) sont opt-in, signées, sauvegardées.
- **Privacy-first** : la porte `Outbound calls` est OFF par défaut.
  Tant qu'elle n'est pas activée, aucun canal sortant (TAXII, SIEM,
  e-mail, webhook, registres, refresh threat feed) ne part de la
  machine.
- **Tout l'historique persistant est dans `~/Library/Application Support/com.sentinel-mcp.desktop/`**
  (SQLite + JSON). Pas de cloud Sentinel.

---

## 2. Architecture fonctionnelle

L'application est composée de onze crates Rust regroupées dans un
workspace et d'une UI Tauri 2 + React 19.

| Crate                | Rôle                                                         |
|----------------------|--------------------------------------------------------------|
| sentinel-protocol    | Types MCP (JSON-RPC, méthodes, transports), enums Portée, `ScopeServeur` |
| sentinel-store       | Persistance SQLite (serveurs, outils, baselines, constats, tags, scopes) — migrations V1/V2/V3 |
| sentinel-scan        | Capture stdio + HTTP, parseur `tools/list`, mode proxy B     |
| sentinel-monitor     | Boucle de surveillance continue, baselines, dérive           |
| sentinel-detect      | Détecteurs (empreinte, rug-pull, poisoning, sosies)          |
| sentinel-alerts      | Moteur d'alertes (sévérité, canaux, déduplication), sinks Splunk / Elastic / Syslog UDP/TCP/TLS |
| sentinel-report      | Génération PDF + JSON, signature Ed25519, mapping conformité |
| sentinel-discovery   | Lecture des configs des 14 clients IA, threat intel feed (bundled + remote refresh + cache) |
| sentinel-stix        | Sérialisation des constats au format STIX 2.1                |
| sentinel-taxii       | Client TAXII 2.1 (push d'un bundle STIX vers une collection) |
| sentinel-cli         | Interface ligne de commande (scan, report, list…)            |

L'interface Tauri appelle ces crates via les commandes exposées par
l'application desktop (voir [annexe](#annexe--cartographie-des-commandes-tauri)).
Chaque action de l'UI (bouton, toggle, dialog) est câblée à une
commande Tauri et persiste son effet.

Côté Rust, un module `outbound.rs` centralise la **porte « Outbound
calls »** : chaque commande qui sortirait sur le réseau (TAXII, SIEM,
e-mail, webhook, registres, refresh threat feed) la consulte en début
d'exécution et échoue de façon homogène avec le message
`Outbound calls disabled in Settings — TAXII push blocked.` quand le
toggle est OFF.

---

## 3. Page Overview

Tableau de bord d'arrivée. Donne en un coup d'œil l'état de santé de
toute la surface MCP de la machine.

### Cartes en haut

- **Servers detected** : nombre de serveurs MCP actuellement déclarés
  par au moins un client IA (avec point vert/orange/rouge selon le
  pire état observé).
- **At risk** : serveurs marqués rouge (constats critiques non
  résolus). Si 0, l'opérateur sait qu'aucun feu rouge n'est ouvert.
- **Critical findings** : nombre de constats de sévérité critique
  encore ouverts.
- **Time to first red** : temps entre le démarrage de l'application et
  le premier constat critique. Métrique « cinq minutes » du module
  rapport.

### Bloc Recent findings

Affiche les 5 derniers constats ouverts, tous serveurs confondus, avec
leur titre et le serveur concerné. Sert d'entrée rapide vers la page
Alerts.

### Bloc Compliance snapshot

Liste les contrôles de conformité couverts par les détections actives
(ISO 27001, OWASP, SOC 2, OWASP MCP, SAFE-MCP). Donne une vue à plat
sans avoir à entrer dans la page Compliance.

---

## 4. Page Discovery

C'est l'écran de découverte. Sentinel lit, **localement**, la config de
chaque client IA installé sur le Mac, et liste les serveurs MCP qu'il
déclare.

### Clients IA détectés

Pour chaque client IA, Sentinel sait :
- où est son fichier de config (chemin affiché),
- combien de serveurs MCP il déclare,
- s'il a un « block MCP » dans sa config (champ `mcpServers`).

Clients couverts :

- Claude Code CLI (`~/.claude.json`)
- Claude Desktop (`~/Library/Application Support/Claude/...`)
- Cursor
- Windsurf (`~/.codeium/windsurf/mcp_config.json`)
- Continue
- Zed
- VS Code (`~/Library/Application Support/Code/User/settings.json`)
- Aider
- Goose
- Codex (`~/.codex/config.toml`)
- Antigravity
- LM Studio
- Open WebUI
- Sketch

Chaque carte client affiche aussi les éventuels diagnostics (« app
bundle not found in /Applications », « mcp_config.json is empty »).

### Portée user vs portée projet

Les configs qui supportent les deux modèles (`mcpServers` racine vs
`projects.<chemin>.mcpServers`, typiquement Claude Code CLI) sont
parsées en distinguant la **portée** de chaque serveur :

- `scope = user` : déclaration globale pour le compte macOS.
- `scope = project:<chemin>` : déclaration spécifique à un dossier de
  travail.

Le scope est persisté en base (colonne dédiée, migration V3) et
visible dans toute l'UI (badge sur les cartes serveur, filtre dédié
dans la page Inventory, ligne « Scope » dans le drawer de détail avec
le chemin complet en tooltip).

### Bouton Scan now

Relance une découverte complète. Émet à la fin un toast « Scan complete
· N clients · M declared servers » (déduplique les toasts répétés en
moins de 5 secondes).

### Bouton Probe live

Disponible sur les clients qui exposent des serveurs (typiquement
Claude Code CLI). Lance une **sonde active** sur chaque serveur déclaré
par ce client : démarre l'exécutable MCP en stdio, envoie `initialize`
puis `tools/list`, capture l'inventaire d'outils, écrit l'empreinte
canonique, ferme proprement le processus. Aucune écriture, aucune
exécution d'outil.

La sonde résout les binaires absolument (npx, uvx…), augmente le PATH
pour fonctionner depuis launchd, et applique un timeout de sécurité.

### Threat intelligence feed

Liste curatée de paquets MCP problématiques (typo-squats, descriptions
empoisonnées, rug-pulls, exfiltration). Chaque entrée porte :

- ID interne (MCP-2026-XXX)
- Nom de paquet
- Sévérité (critical, high, medium, low)
- Raison technique
- Tags de classification (SAFE-T1001, SAFE-T1201, lookalike, rug-pull,
  data-exfil, account-compromise, maintainer-revoked, ownership-transfer…)
- Date de publication
- Nombre de **matches** : combien de serveurs de l'inventaire actuel
  correspondent à cette signature.

Le feed est filtrable par paquet ou par ID.

**Cascade de chargement** (déterministe, jamais aveugle) :

1. Si `auto_refresh_enabled = ON` et `outbound_lookups = ON` et que le
   cache disque est absent ou plus vieux que 24 h → GET HTTP sur l'URL
   configurée, validation YAML, écriture du cache
   (`threat_feed_cache.yaml` + métadonnées `threat_feed_cache.meta.json`
   contenant `sha256`, `fetched_at`, `source`).
2. Sinon, si le cache disque existe → on l'utilise.
3. Sinon → fallback final sur le YAML **bundled** dans le binaire
   (`data/threat_feed.yaml`), toujours disponible hors ligne.

La carte Settings « Threat Intel Feed » expose l'URL, le toggle d'auto-
refresh, l'âge de la dernière entrée, le compteur d'entrées et un
bouton « Refresh now » (désactivé avec tooltip si `Outbound calls` est
OFF). Un task tokio détaché tente un refresh d'arrière-plan respectant
les deux toggles, sans bloquer l'UI.

### Panneau Lookalike scan

Bouton **Scan registries** qui interroge en HTTPS les quatre registres
publics :

- PulseMCP (`api.pulsemcp.com`)
- Smithery (`registry.smithery.ai`)
- mcp.so (`mcp.so/api`)
- Registre officiel MCP (GitHub `modelcontextprotocol/servers`)

Pour chaque serveur déclaré, calcule un score de similarité Jaro-Winkler
combiné nom + description avec chaque entrée de registre. Tout match
au-dessus de 0.85 avec un nom **différent** du serveur déclaré est
remonté comme candidat sosie, classé en sévérité :

- **critical** si score ≥ 0.92
- **high** si score ≥ 0.88
- **medium** sinon

Le but : repérer un typo-squat ou un fork hostile avant qu'il ne soit
adopté.

---

## 5. Page Inventory

Vue à plat de tous les serveurs MCP que Sentinel a observés sur la
machine, sur toutes les sessions et tous les clients. Source de vérité
unique.

### Filtres

- **Color** : All / Green / Orange / Red — selon la pire sévérité de
  constats sur le serveur.
- **Transport** : All / Stdio / HTTP.
- **Status** : All / Approved / Unknown / Suspect / Blocked — reflète
  les décisions de la page Approvals.
- **Scope** : All / User / Project — distingue les serveurs déclarés
  globalement pour le compte macOS et les serveurs déclarés sous un
  dossier de travail (Claude Code `projects.<chemin>`). Quand un
  dossier est sélectionné, un sous-filtre liste les projets connus.
- **Tags** : multisélection sur l'univers des tags opérateur déjà
  posés (autocomplete sur la frappe, sélection cumulative, clear en
  un clic).
- **Recherche libre** par endpoint, transport, scope.

### Carte serveur

Chaque carte affiche :
- L'identifiant lisible (commande + args, ex. `npx -y @modelcontextprotocol/server-filesystem`)
- Le badge de transport
- Le badge de scope (`user` ou `project: <basename>` avec chemin
  complet en tooltip)
- Le statut d'approbation (libellé court)
- Les portées inférées (filesystem, database, network, external_api,
  secrets, browser, read, write, unknown)
- Les **chips de tags** opérateur (les N premiers, avec compteur
  d'overflow et tooltip complet)
- Le nombre d'outils
- Last seen (date du dernier contact)

### Drawer de détail

Clic sur une carte ouvre un panneau latéral persistant qui contient :

- **At a glance** : compteur d'outils, empreinte canonique SHA-256,
  first seen, last seen, scopes, scope user/project (avec chemin de
  projet copiable), `package_id` quand reconnu.
- **Tags** : éditeur dédié (chips supprimables, autocomplete sur
  l'univers de tags déjà connus de la base, normalisation
  trim + lowercase + max 32 caractères, limite 32 tags par serveur,
  bouton « Save tags »).
- **Tools** : la liste complète des outils du serveur avec leur
  description (telle que renvoyée par `tools/list`) et leur input
  schema (JSON Schema déplié).
- **Investigations (N)** : historique des notes d'enquête déposées par
  les opérateurs sur ce serveur.
- **Findings** : tous les constats associés à ce serveur, ouverts ou
  résolus.
- **Boutons en bas** : Approve, Investigate, Block (mêmes effets que
  sur la page Approvals).

### Tags opérateur

- Côté Rust : commandes `server_set_tags` (écriture validée :
  trim + lowercase + dédup + plafonds) et `server_list_tags` (union
  triée de tous les tags posés sur l'inventaire).
- Côté SQLite : colonne `tags TEXT NOT NULL DEFAULT '[]'` ajoutée par
  la migration V2 (JSON array, pas de table dédiée tant que le volume
  reste faible).
- Côté UI : composant `TagsEditor` réutilisé dans le drawer et un
  popover de filtre dans la `FilterBar`.

Cas d'usage : étiqueter prod/staging, ownership, sensibilité, niveau
de risque, équipe propriétaire — sans toucher au modèle de scope ni
au statut d'approbation.

---

## 6. Page Live Scan

Lance une capture **à la demande** sur un serveur MCP, en stdio ou en
HTTP, pour observer son trafic JSON-RPC et remplir l'inventaire.

### Modes de capture

- **Stdio** : Sentinel enveloppe l'exécutable MCP du serveur cible. Il
  démarre le processus, relaie stdin/stdout fidèlement, et observe au
  passage chaque message JSON-RPC. Aucun message n'est modifié.
- **HTTP** : Sentinel agit comme sonde active. Il établit une session
  Streamable HTTP avec le serveur (`POST /mcp` + GET SSE), envoie
  `initialize` puis `tools/list`, capture la réponse, ferme la session.

Le mode Fixture (rejeu de traces capturées) a été retiré — seuls Stdio
et HTTP restent disponibles.

### Sortie

Le panneau de droite affiche un flux temps réel :
- Lignes de logs (« Probing X… », « Probed X — N tools discovered »,
  erreurs)
- Compteurs : événements observés, serveurs nouveaux, outils découverts,
  premier rouge.

L'inventaire est immédiatement mis à jour : les nouveaux serveurs
apparaissent dans Inventory, les nouveaux outils dans le drawer.

### Bannière proxy

Si le mode B (proxy capture) est démarré dans Settings, une bannière
verte en haut du Live Scan indique « Proxy capture · :PORT active »
avec un raccourci Stop.

---

## 7. Page Alerts

Le flux des alertes générées par les détecteurs. Chaque alerte est
attachée à un constat (`finding`) et à un serveur.

### Filtres

- Par **sévérité** : All / Critical / High / Medium (compteurs en pill).
- Par **canal** : All channels / Dashboard / Email / Webhook / SIEM.
- Toggle **Show resolved** : par défaut seules les alertes ouvertes
  sont affichées. Activer le toggle re-fetche la liste avec les
  alertes résolues incluses.

### Carte alerte

Affiche :
- Sévérité (pill rouge / orange / jaune)
- Titre court (ex. « Tool description quotes ~/.ssh »)
- Serveur concerné
- Timestamp
- Détail technique
- **Diff** lisible si le constat vient d'un changement de fingerprint
  (rug-pull) — affiche le diff outil par outil avec les ajouts, les
  suppressions, les renommages.
- Boutons : **Mark as resolved**, **View server**

### Action Mark as resolved

Appelle `resolve_finding` côté Rust. Met à jour l'état du constat à
« résolu » en base, ajoute éventuellement une note de résolution dans
le `detail`. Toast « Resolved · HH:MM » apparaît. La ligne disparaît
sauf si Show resolved est actif.

### Source des alertes

Une alerte peut provenir de :
- une **détection automatique** par le moteur (poisoning, rug-pull,
  combo exfiltration, sosie)
- un **fait** émis par le module de surveillance (nouveau serveur,
  dérive d'empreinte)
- une **règle de canal** (le même constat peut être diffusé sur
  plusieurs canaux : dashboard, e-mail, webhook, SIEM)

Le moteur d'alertes déduplique automatiquement les répétitions par
fenêtre glissante (titre + description), pour éviter le bruit.

---

## 8. Page Approvals

Workflow de revue formelle. Chaque serveur doit être traité avant de
disparaître de cette queue.

### Trois décisions

- **Approve** : marque le serveur comme approuvé. Sa baseline d'outils
  devient la référence pour la détection de rug-pull. Disparaît de la
  queue, apparaît en vert dans l'Inventory.
- **Investigate** : ouvre un dialog dans lequel l'opérateur écrit une
  note d'investigation (≥ 10 caractères) et signe avec son identifiant.
  La note est persistée, attachée à l'audit bundle signé, et visible
  dans le drawer du serveur. Le serveur passe au statut « à
  investiguer » et sort de la queue.
- **Block** : marque le serveur comme bloqué (advisory par défaut). Si
  le mode Enforcement est activé dans Settings, un dialog de
  confirmation s'affiche, montrant le chemin de la config concernée et
  le chemin de la sauvegarde qui sera créée. À la validation, Sentinel
  écrit `<config>.sentinel.<timestamp>.bak`, retire l'entrée du bloc
  `mcpServers`, et conserve une pill « Restore from backup » pour
  permettre une annulation en un clic.

### Bandeau « Restore from backup »

Apparaît dès qu'une suppression enforcement a été effectuée. Un clic
restaure la config originale depuis le `.bak` (refuse de toucher autre
chose qu'un fichier `.sentinel.…bak`).

---

## 9. Page Trust graph

Représentation **clients IA → serveurs MCP → portées** sous forme de
graphe orienté.

### Compteurs en haut

- **AI clients** : nombre total de clients IA détectés.
- **MCP servers** : nombre total de serveurs uniques (déduplication par
  package + commande + args).
- **Max blast radius** : score du client le plus exposé (sert de
  référence pour normaliser les barres).

### Bloc Reachability (canvas)

Force-directed graph :
- Nœuds bleus = clients IA
- Nœuds magenta = serveurs MCP
- Nœuds verts/oranges/rouges = portées (read, write, filesystem,
  database, external_api, network, secrets, browser, unknown)

Cliquer/survoler un nœud illumine ses voisins. Permet de voir d'un
coup d'œil « si je compromets ce client, j'ai accès à quoi ? ».

### Bloc Blast radius (sidebar)

Pour chaque client IA, calcule un score 0..10 selon les portées
qu'il atteint via au moins un serveur :

- secrets : 10
- filesystem + write : 8
- filesystem seul : 4
- database : 6
- external_api : 3
- network : 2

Chaque scope n'est compté qu'une fois par client (la première fois
qu'on l'atteint via un serveur). Les scores sont visualisés via une
barre dégradée vert→jaune→rouge.

### Breakdown

Sous la barre, la liste complète des serveurs accessibles par le
client sélectionné, chacun avec ses portées.

---

## 10. Page Time travel

Rejoueur de tous les envelopes JSON-RPC observés par Sentinel.

### Filtres

- **Server** : tous les serveurs ou un seul.
- **Method** : tous ou une méthode MCP précise (`initialize`,
  `tools/list`, `tools/call`, `notifications/tools/list_changed`…).
- **Direction** : client → serveur ou serveur → client.
- **Range** : aujourd'hui, 7d, 30d, custom.

### Sortie

Liste paginée d'événements. Chaque ligne montre le timestamp, le
serveur, la méthode, la direction, et un aperçu de la charge utile
(headers, taille). Cliquer ouvre l'envelope brute (request ou
response) pour debug.

### Source des événements

- Capture stdio (mode wrapper)
- Capture HTTP (mode active probe)
- Capture proxy mode B (mode passif sur trafic réel)

Sentinel ne stocke jamais le **corps complet** d'une réponse si le
flag « Inspection-in-flight only » est activé (par défaut). Dans ce
cas, seul l'en-tête et la taille sont persistés.

---

## 11. Page Compliance

Cartographie automatique des constats vers les référentiels
réglementaires.

### Quatre cards de référentiels

- **OWASP MCP** (purple) : risques spécifiques aux serveurs MCP, aux
  outils et aux prompts.
- **SAFE-MCP** (blue) : taxonomie comportementale de menaces (T1001 :
  poisoning ; T1201 : rug-pull).
- **SOC 2** (green) : Trust Services Criteria — sécurité,
  disponibilité, confidentialité (CC6.1, CC7.1, CC7.2).
- **ISO 27001** (orange) : contrôles de gestion des actifs et de
  logging (A.12.4.1, A.12.4.3, A.12.6.1, A.13.1.1, A.14.2.2, A.8.1.1).

Chaque card liste les contrôles couverts, le nombre de findings
mappés (« 0 findings mapped » si aucun constat ne touche encore ce
contrôle), et le pourcentage de couverture.

### Bouton Generate signed report

Lance la génération du bundle d'audit (voir page Report).

### Bloc Methodology

Explique brièvement comment Sentinel mappe un constat à un contrôle :
pour chaque type de constat (`PoisoningDescription`, `RugPullOutil`,
`ServeurInconnu`, etc.), un mapping statique vers les identifiants des
référentiels. Le détail est ouvrable.

### Filtre

Champ « Filter by framework or control identifier » qui filtre les
cards et leurs contrôles (ex. `MCP09`, `SAFE`, `A.12`).

---

## 12. Page Report

Génération du **bundle d'audit signé** que Sentinel produit pour les
auditeurs.

### Onglets

- **Executive summary** : résumé pour direction (serveurs détectés,
  non approuvés, à risque, constats ouverts, période analysée).
- **Inventory** : liste détaillée de chaque serveur, ses outils, ses
  portées, son empreinte canonique, son statut d'approbation.
- **Changelog** : historique des changements d'empreinte sur la
  période (diffs lisibles, raisons).
- **Compliance** : tableau croisé constats × contrôles, comme dans la
  page Compliance.
- **Remediation** : plan d'action généré automatiquement à partir des
  constats ouverts (par exemple « Bloquer le serveur X qui présente
  une description suspecte »).

### Actions

- **Open PDF** : ouvre le PDF généré dans le lecteur système.
- **Open JSON** : ouvre l'export JSON structuré (utile pour
  intégration avec un outil tiers).
- **Regenerate bundle** : régénère un bundle complet à partir de
  l'état actuel de la base. Le bundle est signé Ed25519 et
  horodaté.

### Pill d'état

- **DRAFT — NOT SIGNED YET** : le bundle n'a pas encore été signé.
- **SIGNED** : la dernière régénération a été signée avec succès. Le
  fichier de signature est disponible dans le dossier de l'application.

### Vue « bundle paths »

Bloc dépliable qui affiche les chemins absolus du PDF, du JSON et du
fichier de signature. Pratique pour les uploader vers une plateforme
GRC.

### Export STIX 2.1 et push TAXII 2.1

Une fois le bundle généré, Sentinel peut :
- exporter les constats au format **STIX 2.1** (`stix_export_bundle`,
  JSON bundle conforme schéma 2.1) ;
- pousser ce bundle sur une **collection TAXII 2.1** externe
  (`taxii_test_send` / `taxii_save_config` / `taxii_get_config`).

L'envoi TAXII passe par la porte `Outbound calls` : tant qu'elle est
OFF, la commande échoue immédiatement avec le message canonique. La
configuration TAXII (URL, collection ID, API root, credentials) est
persistée à côté de `siem.json` dans le dossier de support
applicatif.

---

## 13. Page Settings

Configuration de l'application. Tous les paramètres sont persistés
dans `settings.toml` (ou `siem.json` pour le canal SIEM,
`taxii.json` pour TAXII).

### Section Live monitoring

- **Background sweep interval** : 10s / 30s / 60s / 5min. Période à
  laquelle Sentinel relance une discovery + lookup léger pour mettre
  à jour la sidebar « Live · 30s ».

### Section Capture

- **Default scan mode** : Stdio ou HTTP. Utilisé quand l'opérateur
  démarre un scan sans préciser le mode.
- **HTTP capture port** : port local sur lequel l'intercepteur HTTP
  écoute par défaut.

### Section Proxy capture (mode B) — experimental

- **Enable proxy** : démarre/arrête le proxy axum.
- **Port** : port local où il écoute (par défaut 8765).
- **Upstream URL** : URL du serveur MCP réel vers lequel le proxy
  relaie le trafic (bit-exact).
- **Start / Stop** : contrôles manuels.
- **Status pill** : STOPPED (orange) ou RUNNING ON :PORT (vert).
- **Events captured** : compteur d'événements observés par le proxy.
- **Client redirect** : URL à donner au client IA pour qu'il passe par
  Sentinel. Bouton Copy.

Le proxy normalise chaque corps de requête et chaque chunk SSE,
détecte les sessions par `Mcp-Session-Id`, et alimente l'inventaire
en temps réel — sans modifier les payloads transmis.

### Section Alerts → Email channel

- Toggle Enable
- SMTP host, port (587 par défaut)
- From, To
- Bouton **Send test email** qui envoie un message factice via le
  même chemin que les alertes réelles.

### Section Alerts → Webhook

- Toggle Enable
- Webhook URL
- Format : Generic, Slack, Teams.
- Bouton **Send test webhook**.

### Section SIEM

Trois sous-onglets :

- **Splunk HEC** : URL du collector HTTP Event Collector, token HEC,
  sourcetype optionnel.
- **Elastic** : URL de base, index cible, auth Basic optionnelle.
- **Syslog** : adresse `host:port`, sélecteur de transport
  **UDP (default) / TCP / TLS** :
  - UDP : RFC 5424 historique (un datagramme par alerte).
  - TCP : framing **octet-counted** (`<LEN> <MSG>`), connexion
    persistante avec timeout et retry.
  - TLS : **RFC 5425** (TCP + TLS), avec champ « TLS CA PEM » et
    bouton **Pick** (sélecteur de fichier `siem_pick_ca_pem`) pour
    référencer un certificat racine personnalisé.

Boutons **Save** (persiste la config dans `siem.json`) et **Send test
alert** (envoie un message d'événement de test via le sink choisi).
La config persiste les secrets dans le fichier de support
applicatif — jamais loggés.

### Section TAXII

- URL de discovery, API root, ID de collection, méthode d'auth (basic
  / bearer / aucune), secret.
- Bouton **Save** (persiste dans `taxii.json`), bouton **Send test**
  qui pousse un STIX bundle minimal et reflète le code de retour HTTP.
- Toute action TAXII passe par la porte `Outbound calls`.

### Section Threat Intel Feed (v0.3)

- **URL** : URL du fichier `threat_feed.yaml` à récupérer (par défaut
  le dépôt public GitHub `sentinel-mcp/threat-intel-feed`).
- **Auto-refresh** : toggle ON/OFF. Quand ON, un task tokio
  d'arrière-plan tente une mise à jour périodique (avec un cooldown
  de 24 h, et silencieusement sans réseau si `Outbound calls` est
  OFF).
- **Status** : pill « source » (`remote-cache` / `bundled` / `cold`),
  timestamp `last_refresh`, âge humanisé, compteur `entries`,
  `version` du flux.
- **Refresh now** : force un GET HTTP immédiat. Désactivé avec
  tooltip si `Outbound calls` est OFF.

Le YAML bundled reste toujours présent comme filet de sécurité — la
cascade `remote → cache → bundled` garantit qu'aucun écran n'est
jamais vide.

### Section Retention

- **Contacts history** : 30d / 60d / 90d.
- **Findings** : 90d / 180d / 365d.
- **Alerts** : 30d / 90d / 180d.

Au-delà de la fenêtre, les enregistrements sont purgés à chaque
démarrage.

### Section Privacy

- **Inspection-in-flight only** : Sentinel n'enregistre jamais le
  corps complet des messages MCP. Activé par défaut, verrou affiché.
- **Outbound calls** : **OFF par défaut**. Quand OFF, aucune commande
  Tauri ne sort sur le réseau (registres lookalikes, refresh threat
  feed, TAXII, SIEM, e-mail, webhook). Chaque commande renvoie le
  message canonique
  `Outbound calls disabled in Settings — TAXII push blocked.`
  et l'UI affiche la même tooltip sur les boutons concernés. Le
  centralisme côté Rust est porté par le module `outbound.rs`.

### Section Enforcement (experimental)

- Toggle off par défaut.
- Quand activé, la décision **Block** dans Approvals et le drawer
  réécrit la config du client IA concerné pour retirer l'entrée du
  bloc `mcpServers`. Une sauvegarde timestampée est créée à côté.

Le toggle est volontairement caché dans Settings : Sentinel reste
**advisory** par défaut.

### Section About

- **App version** : version applicative actuelle.
- **Compliance frameworks supported** : pills des référentiels
  reconnus.
- **Read-only by default** : badge SAFE.

---

## 14. Shell desktop, command palette et menubar

L'application n'est pas qu'une succession de pages : le shell desktop
ajoute trois éléments qui rendent Sentinel utilisable comme un outil
de fond.

### Command palette (`⌘K`)

Composant overlay déclenché par le raccourci `⌘K` (macOS) ou
`Ctrl+K`. Il accepte trois familles de commandes :

- **Pages** : sauter directement à `overview`, `discovery`,
  `inventory`, `scan`, `alerts`, `approvals`, `trust-graph`,
  `timeline`, `compliance`, `report`, `settings`.
- **Serveurs** : recherche floue sur les serveurs de l'inventaire.
  Sélectionner un serveur dépose son identifiant en session et ouvre
  l'Inventory en faisant pop le drawer correspondant.
- **Actions** : raccourcis vers les opérations courantes (lancer un
  scan, ouvrir le dernier rapport…).

Le palette est piloté par `useCommandPalette` (hook clavier) et
monté au niveau racine pour rester accessible quelle que soit la
page active.

### Onboarding (Welcome screen)

Au premier lancement, une page de bienvenue explique en quelques
écrans ce que Sentinel observe, ce qu'il ne fait pas, et où sont
stockées les données. Le passage est tracé dans `useOnboarding`, ce
qui évite de la réafficher ensuite.

### Tray icon menubar + compteur d'alertes

Sentinel installe une **icône menubar** macOS avec :

- **Open Sentinel** : ramène la fenêtre principale au premier plan.
- **Run scan now** : émet un événement
  `sentinel://tray-scan-requested` que le frontend reçoit, route vers
  la page Live Scan, et déclenche `start_scan` avec les défauts
  configurés.
- **Quit Sentinel** : quitte proprement (arrête les tasks
  d'arrière-plan).

À côté de l'icône, un compteur d'alertes ouvertes est rafraîchi
toutes les 30 secondes (`tokio::time::interval`) et propagé via un
événement `sentinel://alerts-count-changed` que les badges UI
écoutent aussi.

### Fermeture vers la barre

Cliquer sur le bouton rouge ferme la fenêtre mais laisse l'app
tourner derrière l'icône menubar — la surveillance temps réel
continue.

### Toaster et drag strip

- Toaster commun pour toutes les notifications (succès, erreur,
  warning) avec dédup courte fenêtre.
- Drag strip transparent sur tout le haut de la fenêtre, pour bouger
  l'app où qu'on clique (`data-tauri-drag-region`).

---

## 15. Différenciateurs — le vrai cœur du produit

Ce que les outils MCP existants ne font pas, et que Sentinel implémente
de façon native.

### Active probe MCP (différenciateur n°1)

Sentinel ne se contente pas de lire les fichiers de config. Il **parle
réellement** à chaque serveur MCP en stdio ou HTTP, lui envoie
`initialize`, puis `tools/list`, et capture la réalité opérationnelle.
Conséquence : si un serveur ment dans son `mcpServers` ou si le
package n'est pas celui qu'il prétend, Sentinel le voit.

### Empreinte canonique et anti-rug-pull (différenciateur n°2)

Sentinel sérialise chaque inventaire d'outils en **JSON canonique** :
outils triés par nom, clés triées récursivement, encodage stable,
input schema complet inclus. Calcule un SHA-256 sur cette
représentation. Cette empreinte est **persistée comme baseline** dès
l'approbation. Chaque session suivante recalcule l'empreinte ; toute
divergence par rapport à la baseline génère un constat de rug-pull,
**même si le serveur a tenté de masquer le changement** (ajout d'outil,
description modifiée, paramètre par défaut changé, enum élargi).

### Threat intel et lookalikes (différenciateur n°3)

Sentinel maintient un feed curatif de paquets MCP problématiques
**bundled** dans le binaire, matche en continu l'inventaire contre ce
feed, et lance des **lookalike scans** contre quatre registres
publics avec une similarité Jaro-Winkler combinée nom + description.
Le feed peut être rafraîchi à la demande ou en arrière-plan depuis
une URL configurable (cascade `remote → cache disque → bundled`),
sans jamais devenir aveugle même hors ligne.

### Trust graph et blast radius (différenciateur n°4)

Sentinel calcule par client IA un score de surface d'attaque (« blast
radius ») à partir des portées atteignables. Permet de prioriser :
« Claude Code CLI atteint secrets + filesystem write → score 18 → cible
prioritaire ». Aucun autre outil MCP ne fournit cette vue.

### Compliance mapping intégré (différenciateur n°5)

Chaque détection est mappée nativement vers OWASP MCP, SAFE-MCP, SOC 2
et ISO 27001. Le rapport signé Ed25519 est utilisable tel quel par un
auditeur, sans retraitement.

### Export STIX 2.1 / push TAXII 2.1 (différenciateur n°6)

Sentinel exporte les constats et indicateurs au format **STIX 2.1**
(bundle JSON) et peut les pousser automatiquement vers une **collection
TAXII 2.1** externe (SOC, GRC, plateforme TIP). Intégration directe
dans les flux de threat intel d'entreprise, sans retraitement.

### Surveillance temps réel (différenciateur n°7)

Sentinel tourne en continu : boucle tokio + file watcher (`notify`)
sur les fichiers de config. Tout changement de `mcpServers` est
détecté en moins de 500 ms, propagé à la base, et la sidebar « Live ·
30s » se met à jour. L'opérateur n'a pas besoin de relancer un scan.

### Scope user/project explicite (différenciateur n°8)

Sentinel distingue les serveurs MCP **globaux à l'utilisateur** et
ceux **déclarés sous un projet** (typiquement
`projects.<chemin>.mcpServers` dans Claude Code CLI). Persisté en
base (migration V3), filtrable dans Inventory, affiché en badge sur
chaque carte avec chemin complet en tooltip. Permet de répondre
clairement à « ce serveur est-il actif partout ou seulement dans ce
dossier ? ».

### Tags opérateur (différenciateur n°9)

Système de tags libres (32 max par serveur, 32 caractères max chacun)
posés par l'opérateur depuis le drawer. Persistés en base (migration
V2), exposés en chips sur la carte serveur, en filtre multiselect sur
l'inventory, et en autocomplete partagé entre opérateurs (`server_list_tags`
expose l'union triée déjà connue). Cas d'usage : prod/staging,
ownership, sensibilité, équipe propriétaire.

### Privacy gate centralisée (différenciateur n°10)

Une **seule case Outbound calls** dans Settings contrôle tous les
canaux sortants (TAXII, SIEM, e-mail, webhook, registres, refresh
threat feed). Le code Rust applique la porte de manière homogène via
le module `outbound.rs`, avec un message d'erreur canonique. L'OFF
par défaut garantit qu'une installation neuve ne peut pas
accidentellement appeler un tiers.

---

## 16. Moteurs de détection

Les détections fournies par `sentinel-detect` et déclenchées par la
surveillance continue.

### Détecteur de rug-pull

Compare l'empreinte canonique actuelle d'un serveur à sa baseline
approuvée. Si différence :
- analyse outil par outil (ajout, retrait, renommage)
- pour chaque outil modifié, produit un diff structuré (description,
  paramètres, défauts, enums, schéma imbriqué)
- assigne sévérité selon ampleur et nature du changement
- mappe sur SAFE-T1201 et OWASP MCP09

### Détecteur de tool poisoning

Scanne chaque description d'outil et chaque docstring renvoyé par le
serveur, à la recherche de motifs suspects :
- exfiltration de secrets (`~/.ssh`, `~/.aws`, `AWS_*`, `OPENAI_*`,
  tokens),
- instructions de chargement réseau hostile,
- injection de prompt cachée (« ignore previous instructions », « read
  the contents of … and send via … »).

Mappe sur SAFE-T1001 et OWASP MCP03.

### Détecteur de combinaison exfiltration

Sur une fenêtre de session, repère les combinaisons « lecture de
secret + écriture externe » côté serveur (lecture `~/.ssh` + appel
réseau sortant non-allowlisté, par exemple). Déclenche un constat
critique. Mappe sur SAFE-T1001.

### Détecteur de sosies (lookalikes)

Pour chaque serveur déclaré, calcule similarité Jaro-Winkler combinée
nom + description avec chaque entrée du registre public. Tout match >
0.85 avec un nom différent est remonté avec sévérité critical/high/medium.

### Empreinte par outil et par serveur

Calcul individuel par outil + agrégé par serveur. Permet de cibler le
diff exactement sur l'outil incriminé, sans tout réauditer.

### Validation contre corpus d'attaques

Sentinel maintient un corpus interne de scénarios d'attaque (synthetic
demos : rug-pull, poisoning, sosies). Chaque release est validée en
continu contre ce corpus pour mesurer la précision de détection.

---

## 17. Référentiels de conformité

Le mapping est natif et défini dans `sentinel-report` (mod
`mapping_conformite`).

### OWASP

- **A07 — Identification and Authentication Failures** :
  authentification cassée côté agent (token MCP exposé en clair).

### OWASP MCP

- **MCP03 — Tool Poisoning** : description d'outil hostile, instructions
  cachées.
- **MCP09 — Shadow MCP Server** : serveur déclaré mais non identifié,
  ou serveur ayant subtilement changé d'identité.

### SAFE-MCP

- **SAFE-T1001 — Tool Description Poisoning**
- **SAFE-T1201 — Rug Pull / Tool Behavior Change**

### SOC 2

- **CC6.1** — Logical and Physical Access Controls
- **CC7.1** — System Operations / Change Management
- **CC7.2** — System Operations / Anomaly Detection

### ISO 27001

- **A.12.4.1** — Event Logging
- **A.12.4.3** — Administrator and Operator Logs
- **A.12.6.1** — Management of Technical Vulnerabilities
- **A.13.1.1** — Network Controls
- **A.14.2.2** — System Change Control Procedures
- **A.8.1.1** — Inventory of Assets

Chaque constat porte le ou les identifiants des contrôles auxquels il
contribue. Le rapport signé compile la couverture par contrôle.

---

## 18. Surveillance temps réel

### Boucle tokio + file watcher

Au démarrage, Sentinel lance un task tokio détaché qui :
- toutes les 10/30/60s (selon paramètre), relance une découverte
  légère, met à jour les caches, émet un événement « tick » à l'UI ;
- enregistre les compteurs vitaux (serveurs vus, constats ouverts,
  premier rouge) ;
- propage les changements via les listeners Tauri vers React (SWR
  revalide automatiquement).

En parallèle, un file watcher `notify` surveille les chemins des
fichiers de config des clients IA. Toute modification → discovery
ciblée + propagation immédiate.

### Boucle de refresh du threat feed

Un second task tokio (`lancer_refresh_threat_feed`) gère
l'actualisation du flux threat-intel à distance, dans le respect des
toggles :

- ne se déclenche que si `auto_refresh_enabled = ON` et
  `outbound_lookups = ON`,
- cooldown de 24 h entre deux tentatives,
- écriture atomique du cache et de ses métadonnées (`sha256`,
  `fetched_at`, `source`),
- émission de l'événement `sentinel://threat-feed-refreshed` à l'UI
  pour rafraîchir le compteur et le timestamp.

### Boucle de compteur d'alertes

Un troisième task tokio met à jour le compteur d'alertes ouvertes
exposé dans le titre de la tray icon menubar et propage la valeur via
`sentinel://alerts-count-changed`.

### Effet pour l'utilisateur

- Installer un MCP via `claude mcp add ...` → il apparaît dans
  Discovery + Inventory en moins de 30 secondes, sans relancer
  l'application.
- Modifier `~/.claude.json` à la main → idem.
- Désactiver un serveur → il bascule en disabled dans Inventory.
- Le badge d'alertes (sidebar + tray) se met à jour seul.

### Coût

- < 1 % CPU au repos
- < 50 MB RSS (Tauri + Rust + WebView)
- Aucun thread Rust bloqué (tout en async)

---

## 19. Posture de sécurité et confidentialité

### Read-only par défaut

Sentinel n'altère **jamais** une config sans le toggle Enforcement
activé explicitement. L'opérateur a une porte d'entrée claire pour
permettre les modifications.

### Outbound calls — OFF par défaut

Le toggle global `privacy.outbound_lookups` (Settings → Privacy) est
**désactivé** sur une installation neuve. Tant qu'il l'est, le module
`outbound.rs` bloque, avec un message d'erreur canonique, **toutes**
les commandes Tauri qui sortiraient sur le réseau :

- lookups registres lookalikes (PulseMCP, Smithery, mcp.so, GitHub
  MCP),
- refresh du threat feed (`threat_feed_refresh`),
- canal e-mail (`test_email_channel`),
- canal webhook (`test_webhook_channel`),
- canal SIEM (`siem_test_send`),
- push TAXII (`taxii_test_send`).

L'utilisateur active la porte volontairement, ce qui clarifie l'audit
trail : ce qui sort, sort parce qu'il l'a permis.

### Stockage local exclusif

- Base SQLite : `~/Library/Application Support/com.sentinel-mcp.desktop/sentinel.db`
- Settings : `settings.toml` à côté.
- SIEM config : `siem.json` à côté (secrets non chiffrés — accès
  protégé par les ACL macOS sur le dossier).
- TAXII config : `taxii.json` à côté (mêmes conditions).
- Cache threat feed : `threat_feed_cache.yaml`
  + `threat_feed_cache.meta.json` à côté.
- Bundles signés : sous-dossier `reports/`.

Aucun téléversement vers un serveur Sentinel. Aucune télémétrie.

### Signature Ed25519

Le bundle d'audit produit en sortie est signé avec une paire de clés
Ed25519 stockée dans le dossier de support. La signature est
vérifiable hors-ligne par n'importe quel tiers via la clé publique
embarquée dans le bundle.

### Distribution signée et notarisée Apple

L'application est **signée Developer ID Application** et **notarisée
Apple** (notarization ticket agrafé au bundle). Conséquence : elle
s'installe sans avertissement Gatekeeper sur n'importe quelle machine
macOS, sans manipulation `xattr` ni clic-droit « Ouvrir ».

### Sandbox Tauri 2

- CSP désactivée seulement pour permettre les SVG inline du Trust
  graph, sinon stricte.
- Aucun accès filesystem global : les commandes Rust qui lisent /
  écrivent sont enumérées et auditables (voir l'annexe).
- Aucun shell exec arbitraire : seul le wrapper stdio spawne des
  processus, et seulement après résolution absolue du binaire.

### Syslog TLS pour les déploiements stricts

Le sink Syslog peut s'opérer en **TCP + TLS (RFC 5425)** avec une CA
PEM choisie via dialog filesystem. Convient aux environnements où
UDP n'est pas autorisé et où le trafic vers le SIEM doit transiter
chiffré.

---

## 20. Limites connues

- Couverture macOS uniquement en v0.3 (Apple Silicon — Tauri 2).
- Pas de plugin Cursor / Continue / Aider pour interception en flux —
  passage par le proxy mode B nécessaire si on veut capter le trafic
  HTTP runtime.
- Pas de mode multi-machine : un Sentinel par poste de travail
  développeur.
- Lookalike scan n'agrège pas encore les similarités sur les enums
  d'outils — uniquement nom + description, plus l'overlap d'outils.
- L'auto-refresh du threat feed se déclenche au plus une fois par
  24 h ; pour vérifier immédiatement il faut le bouton « Refresh now ».
- Les secrets SMTP / SIEM / TAXII sont stockés en clair dans le
  dossier de support — la protection repose sur les ACL macOS.

---

## Annexe — Cartographie des commandes Tauri

L'application expose ses commandes regroupées par module :

- **Scan / discovery** : `start_scan`, `stop_scan`, `scan_progress`,
  `discover_system`, `probe_server`, `compute_trust_graph`,
  `list_threats`.
- **Inventory / findings** : `list_servers`, `get_server_detail`,
  `list_findings`, `resolve_finding`, `list_baselines`,
  `list_observed_events`.
- **Approbations / investigations** : `apply_approval`,
  `create_investigation`, `list_investigations`.
- **Enforcement** : `enforcement_remove_server`, `enforcement_restore`.
- **Proxy** : `start_proxy`, `stop_proxy`, `proxy_status`.
- **Lookalikes** : `scan_lookalikes`.
- **Tags** : `server_set_tags`, `server_list_tags`.
- **Threat feed** : `threat_feed_refresh`, `threat_feed_status`.
- **SIEM** : `siem_test_send`, `siem_save_config`, `siem_get_config`,
  `siem_pick_ca_pem`.
- **STIX / TAXII** : `stix_export_bundle`, `taxii_save_config`,
  `taxii_get_config`, `taxii_test_send`.
- **Alerts** : `list_alerts`, `test_email_channel`, `test_webhook_channel`.
- **Settings** : `get_settings`, `save_settings`, `set_live_interval`,
  `get_live_status`.
- **Reports** : `generate_report`, `open_report_file`,
  `executive_summary`, `compliance_references`.
- **App** : `app_version`.

Chaque commande est testée unitairement et intégrée via la suite
`cargo test --workspace`.

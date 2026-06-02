# Sentinel MCP — Catalogue complet des fonctionnalités

Sentinel MCP est un outil de découverte, fingerprinting, surveillance et audit
des serveurs MCP (Model Context Protocol) qu'un Mac de développeur expose à
ses agents IA. Cette page liste **toutes** les fonctionnalités livrées dans
la version 0.2.0 — à quoi elles servent, dans quel cas elles se déclenchent,
et quelles questions de sécurité ou de conformité elles résolvent.

> Note v0.3 : ajoute l'export **STIX 2.1 / push TAXII 2.1** (canal
> d'intégration SOC/GRC) et la **signature Developer ID + notarisation
> Apple** du bundle desktop (installation sans avertissement Gatekeeper).

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
14. [Différenciateurs](#14-différenciateurs-le-vrai-coeur-du-produit)
15. [Moteurs de détection](#15-moteurs-de-détection)
16. [Référentiels de conformité](#16-référentiels-de-conformité)
17. [Surveillance temps réel](#17-surveillance-temps-réel)
18. [Posture de sécurité et confidentialité](#18-posture-de-sécurité-et-confidentialité)
19. [Limites connues](#19-limites-connues)

---

## 1. Vue d'ensemble

### À quel problème répond l'outil

Les agents IA modernes (Claude Desktop, Claude Code, Cursor, Windsurf,
Continue, VS Code, Zed, Aider, Goose, Codex, Antigravity, LM Studio…) se
connectent à des **serveurs MCP** qui exposent des outils (fichiers, base
de données, API externes, secrets, navigateur, etc.). Ces serveurs sont
souvent installés à coup de `npx -y @org/...`, sans audit. Ils peuvent :

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

### Garanties par défaut

- **Read-only par défaut** : Sentinel n'altère rien. Les actions de
  blocage (enforcement) sont opt-in, signées, sauvegardées.
- **Rien ne quitte la machine sauf si l'opérateur l'autorise** (canaux
  e-mail, webhook, SIEM, lookups registres).
- **Tout l'historique persistant est dans `~/Library/Application Support/com.sentinel-mcp.desktop/`**
  (SQLite + JSON). Pas de cloud Sentinel.

---

## 2. Architecture fonctionnelle

L'application est composée de neuf crates Rust regroupées dans un
workspace et d'une UI Tauri 2 + React 19.

| Crate                | Rôle                                                         |
|----------------------|--------------------------------------------------------------|
| sentinel-protocol    | Types MCP (JSON-RPC, méthodes, transports), enums Portée     |
| sentinel-store       | Persistance SQLite (serveurs, outils, baselines, constats…)  |
| sentinel-scan        | Capture stdio + HTTP, parseur tools/list, mode proxy B       |
| sentinel-monitor     | Boucle de surveillance continue, baselines, dérive           |
| sentinel-detect      | Détecteurs (empreinte, rug-pull, poisoning, sosies)          |
| sentinel-alerts      | Moteur d'alertes (sévérité, canaux, déduplication)           |
| sentinel-report      | Génération PDF + JSON, signature Ed25519, mapping conformité |
| sentinel-discovery   | Lecture des configs des 12 clients IA, threat intel feed     |
| sentinel-cli         | Interface ligne de commande (scan, report, list…)            |

L'interface Tauri appelle ces crates via 42 commandes exposées par
l'application desktop. Chaque action de l'UI (bouton, toggle, dialog)
est câblée à une commande Tauri et persiste son effet.

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

Clients couverts en v0.2.0 :

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

Chaque carte client affiche aussi les éventuels diagnostics (« app
bundle not found in /Applications », « mcp_config.json is empty »).

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

Liste curatée de 17 paquets MCP problématiques connus (typo-squats,
descriptions empoisonnées, rug-pulls, exfiltration). Chaque entrée
porte :

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
- **Recherche libre** par endpoint, transport, scope.

### Carte serveur

Chaque carte affiche :
- L'identifiant lisible (commande + args, ex. `npx -y @modelcontextprotocol/server-filesystem`)
- Le badge de transport
- Le statut d'approbation (libellé court)
- Les portées inférées (filesystem, database, network, external_api,
  secrets, browser, read, write, unknown)
- Le nombre d'outils
- Last seen (date du dernier contact)

### Drawer de détail

Clic sur une carte ouvre un panneau latéral persistant qui contient :

- **At a glance** : compteur d'outils, empreinte canonique SHA-256,
  first seen, last seen, scopes.
- **Tools** : la liste complète des outils du serveur avec leur
  description (telle que renvoyée par `tools/list`) et leur input
  schema (JSON Schema déplié).
- **Investigations (N)** : historique des notes d'enquête déposées par
  les opérateurs sur ce serveur.
- **Findings** : tous les constats associés à ce serveur, ouverts ou
  résolus.
- **Boutons en bas** : Approve, Investigate, Block (mêmes effets que
  sur la page Approvals).

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

Le mode Fixture (rejeu de traces capturées) a été retiré en v0.2.0 —
seuls Stdio et HTTP restent disponibles.

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

---

## 13. Page Settings

Configuration de l'application. Tous les paramètres sont persistés
dans `settings.toml` (ou `siem.json` pour le canal SIEM).

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

### Section SIEM (canal v0.2)

Trois sous-onglets :

- **Splunk HEC** : URL du collector HTTP Event Collector, token HEC,
  sourcetype optionnel.
- **Elastic** : URL de base, index cible, auth Basic optionnelle.
- **Syslog** : adresse `host:port` UDP, format RFC 5424.

Boutons **Save** (persiste la config dans `siem.json`) et **Send test
alert** (envoie un message d'événement de test via le sink choisi).
La config persiste les secrets dans le fichier de support
applicatif — jamais loggés.

### Section Retention

- **Contacts history** : 30d / 60d / 90d.
- **Findings** : 90d / 180d / 365d.
- **Alerts** : 30d / 90d / 180d.

Au-delà de la fenêtre, les enregistrements sont purgés à chaque
démarrage.

### Section Privacy

- **Inspection-in-flight only** : Sentinel n'enregistre jamais le
  corps complet des messages MCP. Activé par défaut, verrou affiché.
- **Outbound calls (registries lookup)** : autorise Sentinel à
  interroger PulseMCP / Smithery / mcp.so / le registre officiel.
  Activé par défaut, désactivable en un clic.

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

## 14. Différenciateurs — le vrai cœur du produit

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

Sentinel maintient un feed curatif de 17+ paquets MCP problématiques,
matche en continu l'inventaire contre ce feed, et lance des
**lookalike scans** contre quatre registres publics avec une
similarité Jaro-Winkler combinée nom + description. Repère les
typo-squats avant l'exécution.

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

---

## 15. Moteurs de détection

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

## 16. Référentiels de conformité

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

## 17. Surveillance temps réel

### Boucle tokio + file watcher

Au démarrage, Sentinel lance un task tokio détaché qui :
- toutes les 10/30/60s (selon paramètre), relance une découverte
  légère, met à jour les caches, émet un événement « tick » à l'UI ;
- enregistre les compteurs vitaux (serveurs vus, constats ouverts,
  premier rouge) ;
- propage les changements via les listeners Tauri vers React (SWR
  revalide automatiquement).

En parallèle, un file watcher `notify` surveille les chemins des
fichiers de config des 12 clients IA. Toute modification → discovery
ciblée + propagation immédiate.

### Effet pour l'utilisateur

- Installer un MCP via `claude mcp add ...` → il apparaît dans
  Discovery + Inventory en moins de 30 secondes, sans relancer
  l'application.
- Modifier `~/.claude.json` à la main → idem.
- Désactiver un serveur → il bascule en disabled dans Inventory.

### Coût

- < 1 % CPU au repos
- < 50 MB RSS (Tauri + Rust + WebView)
- Aucun thread Rust bloqué (tout en async)

---

## 18. Posture de sécurité et confidentialité

### Read-only par défaut

Sentinel n'altère **jamais** une config sans le toggle Enforcement
activé explicitement. L'opérateur a une porte d'entrée claire pour
permettre les modifications.

### Stockage local exclusif

- Base SQLite : `~/Library/Application Support/com.sentinel-mcp.desktop/sentinel.db`
- Settings : `settings.toml` à côté.
- SIEM config : `siem.json` à côté (secrets non chiffrés — accès
  protégé par les ACL macOS sur le dossier).
- Bundles signés : sous-dossier `reports/`.

Aucun téléversement vers un serveur Sentinel. Aucune télémétrie.

### Outbound calls explicites

Les seuls appels réseau sortants sont :
- Lookups registres (PulseMCP, Smithery, mcp.so, GitHub MCP registry) —
  désactivables.
- Canal e-mail (SMTP utilisateur).
- Canal webhook (URL utilisateur).
- Canal SIEM (Splunk HEC, Elastic, Syslog UDP — endpoints utilisateur).

Chaque appel est tracé dans `Time travel` si activé.

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
  écrivent sont enumérées et auditables (42 commandes en tout).
- Aucun shell exec arbitraire : seul `nouveau` (le wrapper stdio)
  spawne des processus, et seulement après résolution absolue du
  binaire.

---

## 19. Limites connues

- Couverture macOS uniquement en v0.2.0 (Apple Silicon — Tauri 2).
- Pas de plugin Cursor / Continue / Aider pour interception en flux —
  passage par le proxy mode B nécessaire si on veut capter le trafic
  HTTP runtime.
- Pas de mode multi-machine : un Sentinel par poste de travail
  développeur.
- Le canal Syslog est UDP uniquement (RFC 5424). TCP/TLS prévu en v0.3.
- Lookalike scan n'agrège pas encore les similarités sur les enums
  d'outils — uniquement nom + description.

---

## Annexe — Cartographie des commandes Tauri

L'application expose 42 commandes Tauri, regroupées par module :

- **Scan / discovery** : `start_scan`, `stop_scan`, `scan_progress`,
  `discover_clients`, `probe_live`.
- **Inventory / findings** : `list_servers`, `get_server_detail`,
  `list_findings`, `resolve_finding`, `list_threats`.
- **Approbations** : `apply_approval`, `list_approvals_queue`,
  `create_investigation`, `list_investigations`.
- **Enforcement** : `enforcement_remove_server`, `enforcement_restore`.
- **Proxy** : `start_proxy`, `stop_proxy`, `proxy_status`.
- **Lookalikes** : `scan_lookalikes`.
- **SIEM** : `siem_test_send`, `siem_save_config`, `siem_get_config`.
- **STIX / TAXII** : `stix_export_bundle`, `taxii_save_config`,
  `taxii_get_config`, `taxii_test_send`.
- **Alerts** : `list_alerts`, `test_email_channel`, `test_webhook_channel`.
- **Settings** : `load_settings`, `save_settings`, `set_live_interval`,
  `get_live_status`.
- **Reports** : `generate_report`, `open_report_pdf`, `open_report_json`,
  `list_report_bundles`.
- **Trust graph** : `build_trust_graph`.
- **Compliance** : `list_compliance_mapping`.
- **Time travel** : `list_events`, `get_event_payload`.
- **App** : `app_version`.

Chaque commande est testée unitairement et intégrée via la suite
`cargo test --workspace` (487 tests, 0 échec).

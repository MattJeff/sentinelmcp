# Matrice de détection Sentinel MCP

Spécification de la base de règles : pour chaque technique d'attaque documentée publiquement,
le signal observable côté endpoint, la règle Sentinel correspondante, son seuil et les faux
positifs attendus.

**Statuts d'implémentation :**
- ✅ **Implémentée** — règle active dans le pipeline actuel.
- 🔨 **Cette itération** — implémentée avec cette matrice (nouveaux patterns + détecteur sampling/elicitation). En v0.6 ces règles sont **livrées et câblées** (pipeline hybride `InspecteurPoisoning::inspecter_complet` + proxy stdio temps réel) ; elles sont donc traitées comme ✅ ci-dessous.
- 🗓 **v-next (capteur requis)** — le signal exige un capteur non encore présent (réseau au niveau socket, watch de fichiers mémoire, observation de flux OAuth). Spécifié ici pour éviter une refonte ultérieure. Reste un angle mort assumé (ex. ASI06 côté provenance des écritures mémoire).

Sources principales : SAFE-MCP (T1001, T1201, MCP-16/TC2, MCP-24), OWASP Top 10 for Agentic
Applications 2026 (ASI04, ASI06, ASI07, ASI08, ASI10), OWASP MCP Top 10 (MCP03, MCP09), spec MCP
Authorization (révision juin 2025), règles SIEM Datadog, PoC publics Invariant Labs, recherche Unit 42.

---

## 1. Rug-pull différé (comportement changeant après approbation)

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Post-Audit Description Swap | SAFE-T1201, MCP-16/TC2, OWASP MCP03 | Diff de description entre baseline approuvée et `tools/list` courant | `detect::rugpull` — empreinte SHA-256 canonique par outil + serveur vs baseline | Tout diff = constat ; escalade **Critique** si changement silencieux (`notification_recue == false`) ou si le diff contient un terme sensible (`.env`, `ssh`, `system`) | Mise à jour légitime du serveur (qualifiée par la politique « changement légitime vs attaque », module 2.7) | ✅ |
| Sleeper rug-pull — mutation au 2ᵉ chargement (PoC Invariant `whatsapp-takeover.py`) | SAFE-T1201 | Empreinte divergente entre deux sessions, sans notification | `monitor::derive_lente` — dérive inter-session via baselines persistantes | Diff inter-session sans réapprobation | Redéploiement versionné légitime | ✅ |
| Endpoint Redirection | MCP-16 | Endpoint runtime différent de l'identité canonique | Identité canonique (`package_id`) + détecteur de sosies | Endpoint hors baseline | Migration d'infrastructure annoncée | ✅ |
| Élargissement du schéma de paramètres post-approbation | SAFE-T1201, Datadog | Nouveau paramètre dans l'`inputSchema` d'un outil approuvé | `detect::rugpull` (l'`inputSchema` complet est inclus dans l'empreinte) | Tout ajout de paramètre = diff | Évolution d'API documentée | ✅ |

## 2. Tool poisoning et surfaces resources / prompts

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Instructions impératives dans descriptions / `inputSchema` | SAFE-T1001, OWASP MCP03 | Pattern dans la définition d'outil | `poisoning::patterns` — catégorie `instructions_imperatives` (Haute) | 1 correspondance = constat | Docs d'outils citant des exemples de prompts | ✅ |
| Balises pseudo-système (`[SYSTEM]`, `[ADMIN]`, balise SYS de Llama, etc.) | SAFE-T1001 | Pattern dans tout texte serveur | `poisoning::patterns` — catégorie `balises_pseudo_systeme` (Critique) | 1 correspondance | Très faibles (balises atypiques en texte légitime) | ✅ |
| Enveloppe d'instruction `IMPORTANT` (pattern Invariant / Datadog) | SAFE-T1001 | Balise `IMPORTANT` encadrant des instructions dans une description | `poisoning::patterns` — pattern `balise_important_wrapper` (Critique) | 1 correspondance | Docs utilisant la balise en exemple | ✅ |
| Texte invisible / encodé (zero-width, RTL override, base64 long) | SAFE-T1001 | Caractères d'obfuscation dans les définitions | catégorie `texte_invisible_encode` (Moyenne) | 1 correspondance | base64 légitime (icônes inline, exemples) — sévérité volontairement Moyenne | ✅ |
| Smuggling Unicode (zero-width, contrôles bidi, bloc Tags U+E0000–E007F, échappements ANSI) | SAFE-T1001, FireTail « Unicode tag smuggling », Trail of Bits | Points de code invisibles transportant des instructions au LLM, sur le texte BRUT | `poisoning::mod::detecter_smuggling` — catégorie `smuggling-unicode` (Haute) | 1 classe rencontrée = constat ; extrait listant les points de code `U+XXXX` | Texte propre (accents/emoji légitimes) — couvert par cas bénins du corpus | ✅ |
| Évasion par homoglyphes / variantes « fullwidth » | SAFE-T1001 | Pattern contourné en écrivant `ｉｇｎｏｒｅ` (fullwidth) au lieu de `ignore` | Normalisation **NFKC** (`normaliser_detection`) AVANT application des regex — n'altère jamais l'empreinte canonique | Repli NFKC déterministe, appliqué au seul chemin de détection | Aucun (NFKC standard) | ✅ |
| Line-jumping (instructions injectées après une coupure de ligne — Trail of Bits) | SAFE-T1001 | Directive impérative isolée sur une ligne d'une description | `poisoning::patterns` — catégorie `line_jumping` | 1 correspondance | Docs multi-lignes citant des exemples de prompts | ✅ |
| Injection via `resources/read` et `prompts/get` (toute sortie serveur est non sûre — CyberArk/Invariant) | SAFE-T1001, OWASP MCP03 | Marqueurs d'instruction dans le contenu retourné par resources/prompts | Réutilisation de `InspecteurPoisoning::inspecter_texte` sur les payloads `resources/read` / `prompts/get` (méthodes désormais typées dans `MethodeMcp`) | 1 correspondance, inspection en mémoire uniquement (règle de confidentialité : pas de persistance du contenu) | Resources contenant de la doc sur le prompt engineering | 🗓 (câblage monitor) |
| Fuite d'info de debug via resources (MCP-DPT) | — | Chemins de fichiers système dans les réponses resources | catégorie `chemins_sensibles` appliquée aux payloads resources | 1 correspondance | Serveurs de type filesystem légitimes (allowlist par portée, module 1.7) | 🗓 (câblage monitor) |

## 3. Abus des primitives sampling / elicitation

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Drain de quota par sampling (resource theft — Unit 42) | SAFE-MCP (abus `sampling/createMessage`) | Volume anormal de requêtes `sampling/createMessage` initiées par un serveur | `detect::sampling::DetecteurSampling` — comptage par session/serveur, câblé dans le proxy stdio temps réel | Seuil configurable (défaut : 10 requêtes/session) → **Haute** | Serveurs d'agents légitimes à sampling intensif (seuil ajustable par opérateur) | ✅ |
| Injection persistante via sampling (directive visant la prochaine réponse visible — PoC Unit 42) | SAFE-MCP, Unit 42 | Prompt de sampling contenant une instruction de persistance (« add to your next response ») | `DetecteurSampling` — `inspecter_texte` sur le prompt : catégories `persistance_memoire` + `instructions_imperatives` | 1 correspondance → **Critique** (contourne intégrité des outils ET sandboxing : le monitoring est la défense principale) | Prompts de méta-niveau légitimes (rare) | ✅ |
| Elicitation demandant des secrets (interdit par la spec MCP) | Spec MCP Elicitation | Requête `elicitation/create` demandant mot de passe, clé API, paiement, PII | `DetecteurSampling` — catégorie `demande_secrets` sur le message d'elicitation | 1 correspondance → **Critique** | Formulaires demandant un identifiant non secret (username) — les patterns ciblent les secrets uniquement | ✅ |

## 4. Compromission de contexte persistant (mémoire d'agent)

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Instructions de persistance mémoire dans les sorties serveur (« remember this for all future sessions ») | OWASP ASI06 | Pattern de persistance dans descriptions / contenus retournés | `poisoning::patterns` — catégorie `persistance_memoire` (Haute) | 1 correspondance | Outils de gestion de mémoire légitimes (serveurs memory MCP) décrivant leur fonction | ✅ |
| Écriture dans les stores de mémoire d'agent hors action utilisateur | OWASP ASI06, SAFE-MCP (poisoning de bases vectorielles) | Écriture fichier dans les répertoires mémoire des clients (Claude Desktop, Cursor, Cline) sans entrée utilisateur traçable | Capteur de provenance mémoire (watch des chemins mémoire connus du module discovery) | Écart de provenance = constat | Synchronisation légitime du client | 🗓 (capteur fichiers) |

## 5. Architectures multi-agents (A2A)

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Cascade d'erreur amplifiée (un payload empoisonné répété par plusieurs agents) | OWASP ASI08 | Même payload/instruction observé sur plusieurs sessions/serveurs dans une fenêtre courte | Corrélation cross-session sur le journal d'activité (module 2.6) — lignage des appels | N sessions distinctes portant le même extrait empoisonné dans une fenêtre T | Prompts partagés légitimes (templates d'équipe) | 🗓 (corrélateur) |
| Communication inter-agents non sécurisée | OWASP ASI07 | Trafic agent-à-agent sans mTLS / hors inventaire | Inventaire + détection de nouveaux serveurs (`monitor::new_servers`) couvre la découverte ; contrôle transport en v-next | Tout serveur A2A hors inventaire = ShadowMcp | Nouveaux agents internes légitimes (flux d'approbation 5.9) | ✅ partiel |
| Agent rogue | OWASP ASI10 | Serveur non approuvé actif | `TypeConstat::ShadowMcp` / `NouveauServeur` | Présence hors baseline | Installation volontaire récente | ✅ |

## 6. Exfiltration observable côté endpoint

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Read-Exfil Chain (lecture secret + écriture externe, même session) | SAFE-MCP MCP-24, SAFE-T1201 | Combo `tools/call` lecture-secret puis écriture-externe dans la même `session_id` | `detect::exfiltration::DetecteurExfiltration` | 1 lecture + 1 écriture dans la même session = **Critique** | Workflows légitimes lisant une config puis appelant une API (allowlist par portée) | ✅ |
| Injection de commande par métacaractères shell (`;`, `&&`, pipe vers shell — règle Datadog) | Datadog SIEM | Métacaractères shell + binaire réseau dans un argument ou une description | `poisoning::patterns` — catégorie `injection_commande` (Critique) ; également contrôlée statiquement par `sentinel audit` sur les `args` de config | 1 correspondance (les métacaractères sont rares dans les interactions MCP typiques) | Outils d'exécution shell légitimes documentant leur syntaxe — à allowlister par portée | ✅ |
| Exposition de credentials dans les sorties d'outils (PoC Invariant `direct-poisoning.py`) | Datadog | Sortie d'outil contenant clés SSH, tokens, variables d'env | `inspecter_texte` (catégories `chemins_sensibles`, `lecture_exfiltration`) sur les sorties — en mémoire uniquement | 1 correspondance | Outils de diagnostic affichant des chemins | 🗓 (câblage monitor) |
| Connexion sortante post-lecture (process/socket) | MCP-24 | Lecture fichier sensible puis connexion réseau vers domaine hors baseline dans la même fenêtre | Capteur réseau au niveau process/socket | Fenêtre temporelle configurable | Télémétrie légitime du serveur | 🗓 (capteur réseau) |
| Aggregation Exfiltration (fragments non sensibles combinés) | MCP-24 | Volume cumulé de lectures multi-outils suivi d'une écriture externe | Extension du `DetecteurExfiltration` (compteur de lectures par session) | N lectures + 1 écriture externe | Agents de synthèse légitimes | 🗓 |

## 7. Chaîne d'approvisionnement des registres MCP

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Sosie / typosquat de serveur officiel | OWASP MCP09 | Similarité de nom+description avec un paquet officiel | `detect::lookalikes` — Jaro-Winkler asymétrique **+ confusables Unicode** (skeleton UTS#39, `similarite_nom_confusables`), 4 registres (PulseMCP, registre officiel, Smithery, mcp.so), allowlist des paquets officiels | Seuil de similarité ajusté par asymétrie ; spoofing par homoglyphes (`pаypal` cyrillique) remonté même sous le radar Jaro-Winkler brut | Forks légitimes (allowlist) | ✅ |
| Confusables intra-inventaire (un serveur en imite un autre sous un nom voisin) | OWASP MCP09 | Deux serveurs déclarés au skeleton confusable identique mais aux noms textuellement différents, réutilisant les mêmes outils | `detect::lookalikes::intra_inventory::detecter_sosies_intra` — `similarite_combinee_v2` ≥ 0.85 | Paire signalée hors allowlist | Deux déclarations officielles du même paquet (gardées par `package_id` + allowlist) | ✅ |
| Rug-pull supply-chain par version (cas Postmark : artefact altéré, surface d'outils inchangée) | OWASP ASI04, SAFE-T1201 | L'empreinte SHA-512 du tarball npm change, ou la version résolue bouge, alors que l'inventaire d'outils MCP est identique | `discovery::supply_chain` — attestation npm (`attester`) + diff inter-attestation (`comparer_attestation`) | Même version + empreinte SHA-512 différente = **Critique** (re-publication/tampering, npm garantit l'immutabilité) ; version disponible différente = **Haute** | Mise à jour légitime non encore ré-attestée (à approuver explicitement) | ✅ (volet socket réseau toujours 🗓) |
| Paquet compromis (worms npm Shai-Hulud, registre ClawHub) | OWASP ASI04, CVE-2025-6514, CVE-2025-49596, CVE-2025-54136 | Hash de paquet divergent de la release publiée, version non épinglée | Attestation supply-chain npm (intégrité SHA-512, mainteneurs, date de publication, version épinglée) + threat-intel feed (STIX/TAXII) | Hash hors release publiée ou version non épinglée = constat | Builds locaux non publiés | ✅ partiel (npm couvert ; uvx/git/binaire local = `NonNpm`, 🗓) |

## 8. Détournement des flux OAuth (serveurs MCP distants)

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Token passthrough (anti-pattern interdit par la spec juin 2025) | Spec MCP Authorization | Token reçu du client retransmis tel quel vers un endpoint downstream | Observation du flux HTTP : même token sur deux segments distincts | 1 occurrence = **Critique** (rupture de la frontière d'audience RFC 9068) | Aucun cas légitime (interdit par la spec) | 🗓 (capteur HTTP étendu) |
| Confused deputy (client ID statique + dynamic client registration) | Spec MCP Authorization | Flux d'autorisation sans étape de consentement pour un client nouvellement enregistré | Observation du flux OAuth | Absence de consentement = constat | Consentement hors bande | 🗓 |
| Redirection vers un AS non baseline / replay de refresh token | SAFE-MCP (vol/replay de tokens OAuth) | `redirect_uri` divergent ; usage de refresh token après fin de session | Baseline des AS connus par serveur + corrélation sessions | 1 divergence = **Critique** | Rotation d'AS annoncée | 🗓 |
| Serveur distant sans authentification | OWASP A07 | Endpoint MCP accessible sans mécanisme d'auth | `TypeConstat::SansAuthentification` | Détection à la découverte | Serveurs locaux de dev | ✅ |

## 9. Détection hybride locale, skills/agents et audit statique (v0.6)

Moteurs livrés et câblés en v0.6, tous **locaux** (zéro cloud, zéro token). Le
pipeline `InspecteurPoisoning::inspecter_complet` agrège, dans l'ordre :
patterns regex (+ anti-smuggling Unicode + NFKC + line-jumping), YARA embarqué,
puis juge LLM local optionnel.

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Règles YARA sur la surface d'outils | SAFE-T1001, parité Cisco | Motif YARA sur `description` + `inputSchema` sérialisé | `detect::yara::MoteurYara` (yara-x, Rust pur) — 3 règles embarquées + répertoire `*.yar`/`*.yara` importable | 1 correspondance ; métadonnées (`description`/`categorie`/`severite`) reprises ; timeout 2 s/outil | Faibles (règles ciblées) ; règle importée invalide ignorée sans bloquer | ✅ |
| Verdict sémantique par LLM **local** | SAFE-T1001, ATLAS AML.T0051 | Sens malveillant non capturé par regex/YARA | `detect::llm_judge::JugeLlm` via Ollama (`http://localhost:11434`) | Opt-in explicite ; localhost uniquement ; timeout court ; verdict malveillant → **Poisoning Haute** (signal, pas preuve) | Modèle local de qualité variable — sévérité plafonnée, désactivé par défaut | ✅ (opt-in) |
| Poisoning de skills / sub-agents | SAFE-T1001, ClawHub (~26–36 % des skills publics vulnérables) | Instructions cachées / exfiltration / caractères invisibles dans `SKILL.md` (frontmatter + corps) | `discovery::skills` — chaque artefact passe dans `inspecter_complet` (scopes user/projet/extension) | 1 correspondance par artefact | Docs de skills citant des exemples de prompts | ✅ |
| Transport en clair (config statique) | OWASP MCP07 | Endpoint `http://` vers un hôte distant | `sentinel audit` — `controler_transport` (loopback exemptée) | 1 endpoint distant en clair = constat | `https://` et loopback exemptés | ✅ |
| Secret en dur dans la config | OWASP MCP05 | Valeur de secret structurée (préfixes fournisseurs connus) dans `env`/`args` | `sentinel audit` — `RE_SECRET_VALEUR` (sk-, ghp_, xox*, AKIA, AIza…) | Format à forte confiance uniquement ; valeur masquée dans le rapport | Références indirectes (`${VAR}`, `op://`, `vault:`, `changeme`) jamais flaguées | ✅ |

## 10. Vague D — CVE/OSV, shadowing, OAuth/SSRF, MCPoison, trifecta, sockets

Détecteurs additifs introduits en Vague D. Tous **locaux et hors-ligne**
(zéro appel réseau, base CVE embarquée), conçus pour minimiser les faux
positifs (une version non interprétable, un port loopback ou un retrait de
config n'émettent **rien**).

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Trifecta létale (3 jambes : entrée non fiable + lecture secret + écriture externe, même session) | SAFE-T1201, ATT&CK T1567, Willison/Invariant | Une même session cumule l'ingestion de contenu non fiable (`fetch`/`browse`/`read_email`…), la lecture d'un secret et une écriture externe | `detect::exfiltration::evaluer_trifecta_signal` (`SignalTrifecta`, `vers_constat_trifecta`) — déduplication par jambe | Les 3 jambes coexistantes = **Critique** (plus grave que la combo 2-jambes) ; mapping conformité/rapport câblé | Agent légitime fetch+lecture config+API (l'émission live reste à câbler ; le proxy émet aujourd'hui la combo 2-jambes) | ✅ détecteur + rapport (émission live 🗓) |
| Scan des sorties/erreurs d'outils (ATPA / toxic-flow) | SAFE-T1001, OWASP MCP03 | Poisoning caché dans le `result` **ou** l'`error` d'un `tools/call` (sortie runtime, invisible au scan statique de `tools/list`) | `scan::proxy::inspecter_reponse_outil` — patterns de poisoning sur le contenu de la réponse, corrélée à la requête par `id` JSON-RPC | Seules les réponses d'appels effectivement observés sont inspectées (réponses non corrélées ignorées) ; contenu lu en mémoire, jamais persisté | Sortie d'outil citant un exemple de prompt (bornée par la corrélation `id`) | ✅ (proxy temps réel) |
| Approve-before-run (gate opt-in sur `tools/call`) | OWASP MCP05, défense ToolHive | Appel `tools/call` à risque `Eleve` (écriture externe **portant** un secret) avant relais | `scan::proxy` — `evaluer_risque_tools_call` (Faible/Moyen/Eleve) + `ConfigProxy.enforce` | `enforce=false` (défaut) : constat *advisory*, relais bit-exact. `enforce=true` : appel `Eleve` **retenu** (jamais relayé) + constat « retenu pour approbation » | Aucun en mode détection (advisory) ; en enforce, un appel légitime « envoyer un secret » est retenu volontairement | ✅ (enforce opt-in ; pas de gate UI interactive) |
| Cross-server tool shadowing — collision de nom d'outil | SAFE-T1102, OWASP MCP03 | Deux serveurs DISTINCTS exposent un outil de même nom (résolution ambiguë, ombrage d'un outil de confiance) | `detect::shadowing::detecter_shadowing` (collision de nom) | Outil de même nom porté par ≥ 2 serveurs distincts = **Haute** ; un constat par serveur impliqué | Deux déclarations du même paquet (à dédupliquer en amont par `package_id`) | ✅ |
| Cross-server poisoning — description instruisant à propos d'un autre serveur | SAFE-T1102, SAFE-T1001, OWASP MCP03 | Description d'un outil référençant un outil d'un AUTRE serveur, accolée à un verbe impératif (« before calling send_email… », « override … ») | `detect::shadowing` — `reference_instruite`, fenêtre de proximité verbe ↔ nom d'outil (48 octets), nom d'outil spécifique (≥ 4 car., `_`/`-`/camelCase) | Référence instruite à proximité = **Critique** | Simple mention descriptive sans verbe, ou verbe éloigné du nom (régression couverte par tests) | ✅ |
| Paquet vulnérable à CVE connue (matching CVE/OSV hors-ligne) | OWASP MCP10, OWASP A06, ATT&CK T1195, CVE-2025-6514/49596/53109/53110/53365/53366 | `package_id` + version installée tombant dans une plage affectée d'une CVE connue | `detect::cve_match::rechercher_cve` — base JSON embarquée (`data/cve_mcp.json`), semver simplifié `MAJOR.MINOR.PATCH`, sévérité dérivée du CVSS ; câblé dans `sentinel audit` | Version ∈ [introduced, fixed) = constat (sévérité CVSS) ; version corrigée/postérieure/non interprétable = **rien** (anti-faux-positif strict) | `latest`/version vide jamais signalée ; paquet hors base jamais signalé | ✅ (6 CVE embarquées) |
| Config projet altérée après approbation (MCPoison) | OWASP MCP03/MCP09, CVE-2025-54136 | Le contenu d'une entrée `mcpServers` de projet approuvée **par nom** change (commande/url/transport/args/env/réactivation) ou un serveur est ajouté hors approbation | `discovery::config_baseline` — `comparer_config_projet` + `BaselineConfigsProjet::observer` (diff de contenu par chemin de projet) | Commande/url/transport changés = **Critique** ; args/réactivation = **Haute** ; ajout hors approbation = **Haute** (ShadowMcp) ; env = **Moyenne** | Réordonnance, config identique, serveur retiré, 1ʳᵉ observation d'un projet = **rien** | ✅ |
| Contrôles OAuth / SSRF statiques (serveurs HTTP) | OWASP MCP05, RFC 8707, CWE-918, CWE-522 | URL HTTP vers IP loopback/privée/lien-local (incl. métadonnées cloud `169.254.169.254`, contournement IPv4-mapped IPv6) ; `client_id` OAuth sans `resource`/audience ; secret/jeton embarqué dans l'URL ou relayé via `env` | `discovery::static_http::analyser_serveur_http` — `constat_ssrf` (CWE-918), `constat_oauth` (confused deputy RFC 8707), `constat_passthrough_env`/URL (CWE-522) ; câblé dans `sentinel audit` | IP interne/métadonnées = constat (métadonnées cloud **Haute**) ; `client_id` sans audience = confused deputy ; secret dans l'URL = token passthrough | Nom de domaine public non résolu (pas d'analyse), `env` métier non traité comme passthrough | ✅ (statique) |
| Socket en écoute hors inventaire (NeighborJack) | OWASP MCP09, shadow-mcp | Socket TCP en écoute sur **toutes** les interfaces (`0.0.0.0`/`::`/`*`), port ≥ 1024, sans correspondance dans l'inventaire MCP connu | `discovery::runtime_inspector::InspecteurSockets` (`lsof` macOS/BSD, `ss` Linux) + `correler_avec_inventaire` | Bind-all + port haut + port inconnu = **Moyenne** (la nature MCP n'est pas prouvable statiquement → libellé invite à vérifier) | Loopback ignoré, ports privilégiés (< 1024) ignorés, port présent dans l'inventaire ignoré ; sans `lsof`/`ss` → `Vec` vide best-effort | ✅ (énum. sockets ; scan de process 🗓) |

> Mise à jour des angles morts précédents : le **token passthrough** et le
> **confused deputy** (section 8) passent de 🗓 à **✅ partiel** pour leur volet
> *statique* (URL/`env` d'une config HTTP) via `static_http` ; l'observation du
> flux OAuth en vol (token retransmis runtime, redirect_uri divergent) reste 🗓.
> La **CVE-2025-54136** (section 7) est désormais couverte par le diff de
> contenu des configs projet (D13), au-delà du seul matching CVE par version.

## Récapitulatif des règles ajoutées dans cette itération (🔨)

| Élément | Emplacement | Contenu |
|---|---|---|
| Catégorie `injection_commande` | `sentinel-detect/src/poisoning/patterns.rs` | Métacaractères shell chaînés à un binaire réseau ou un shell (Critique) |
| Catégorie `persistance_memoire` | idem | Instructions de persistance mémoire / réponse suivante (Haute) — couvre ASI06 et l'injection sampling persistante |
| Catégorie `demande_secrets` | idem | Demande de mot de passe, clé API, paiement, PII (Critique) |
| Pattern `balise_important_wrapper` | idem (catégorie `balises_pseudo_systeme`) | Enveloppe d'instruction IMPORTANT (Critique) |
| `DetecteurSampling` | `sentinel-detect/src/sampling.rs` | Volume de sampling, injection persistante via sampling, elicitation de secrets |
| `MethodeMcp` étendu | `sentinel-protocol/src/lib.rs` | `sampling/createMessage`, `elicitation/create`, `resources/read`, `prompts/get` |
| `TypeConstat` étendu | idem | `AbusSampling`, `ElicitationSensible` — câblés dans conformité, sévérité, inventaire, STIX |
| Corpus étendu | `sentinel-detect/src/corpus.rs` | Cas INJ, MEM, ELIC + cas bénins de contrôle des faux positifs |

## Invariants à respecter (rappel)

1. **Confidentialité** : aucune inspection ne persiste le contenu des `params` de `tools/call`, des prompts de sampling ni des réponses resources — inspection en mémoire, seul l'extrait déclencheur (≤ 120 caractères) est conservé dans le constat.
2. **Un mapping de conformité faux est pire que pas de rapport** : toute nouvelle référence dans `compliance.rs` doit pointer un identifiant publié et vérifiable ; pas d'ID SAFE-MCP inventé.
3. **Faux positifs proche de zéro** : toute nouvelle catégorie de patterns doit être accompagnée de cas bénins dans le corpus et mesurée par `RapportCouverture`.

# Matrice de détection Sentinel MCP

Spécification de la base de règles : pour chaque technique d'attaque documentée publiquement,
le signal observable côté endpoint, la règle Sentinel correspondante, son seuil et les faux
positifs attendus.

**Statuts d'implémentation :**
- ✅ **Implémentée** — règle active dans le pipeline actuel.
- 🔨 **Cette itération** — implémentée avec cette matrice (nouveaux patterns + détecteur sampling/elicitation).
- 🗓 **v-next (capteur requis)** — le signal exige un capteur non encore présent (réseau au niveau socket, watch de fichiers mémoire, observation de flux OAuth). Spécifié ici pour éviter une refonte ultérieure.

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
| Enveloppe d'instruction `IMPORTANT` (pattern Invariant / Datadog) | SAFE-T1001 | Balise `IMPORTANT` encadrant des instructions dans une description | `poisoning::patterns` — pattern `balise_important_wrapper` (Critique) | 1 correspondance | Docs utilisant la balise en exemple | 🔨 |
| Texte invisible / encodé (zero-width, RTL override, base64 long) | SAFE-T1001 | Caractères d'obfuscation dans les définitions | catégorie `texte_invisible_encode` (Moyenne) | 1 correspondance | base64 légitime (icônes inline, exemples) — sévérité volontairement Moyenne | ✅ |
| Injection via `resources/read` et `prompts/get` (toute sortie serveur est non sûre — CyberArk/Invariant) | SAFE-T1001, OWASP MCP03 | Marqueurs d'instruction dans le contenu retourné par resources/prompts | Réutilisation de `InspecteurPoisoning::inspecter_texte` sur les payloads `resources/read` / `prompts/get` (méthodes désormais typées dans `MethodeMcp`) | 1 correspondance, inspection en mémoire uniquement (règle de confidentialité : pas de persistance du contenu) | Resources contenant de la doc sur le prompt engineering | 🗓 (câblage monitor) |
| Fuite d'info de debug via resources (MCP-DPT) | — | Chemins de fichiers système dans les réponses resources | catégorie `chemins_sensibles` appliquée aux payloads resources | 1 correspondance | Serveurs de type filesystem légitimes (allowlist par portée, module 1.7) | 🗓 (câblage monitor) |

## 3. Abus des primitives sampling / elicitation

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Drain de quota par sampling (resource theft — Unit 42) | SAFE-MCP (abus `sampling/createMessage`) | Volume anormal de requêtes `sampling/createMessage` initiées par un serveur | `detect::sampling::DetecteurSampling` — comptage par session/serveur | Seuil configurable (défaut : 10 requêtes/session) → **Haute** | Serveurs d'agents légitimes à sampling intensif (seuil ajustable par opérateur) | 🔨 |
| Injection persistante via sampling (directive visant la prochaine réponse visible — PoC Unit 42) | SAFE-MCP, Unit 42 | Prompt de sampling contenant une instruction de persistance (« add to your next response ») | `DetecteurSampling` — `inspecter_texte` sur le prompt : catégories `persistance_memoire` + `instructions_imperatives` | 1 correspondance → **Critique** (contourne intégrité des outils ET sandboxing : le monitoring est la défense principale) | Prompts de méta-niveau légitimes (rare) | 🔨 |
| Elicitation demandant des secrets (interdit par la spec MCP) | Spec MCP Elicitation | Requête `elicitation/create` demandant mot de passe, clé API, paiement, PII | `DetecteurSampling` — catégorie `demande_secrets` sur le message d'elicitation | 1 correspondance → **Critique** | Formulaires demandant un identifiant non secret (username) — les patterns ciblent les secrets uniquement | 🔨 |

## 4. Compromission de contexte persistant (mémoire d'agent)

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Instructions de persistance mémoire dans les sorties serveur (« remember this for all future sessions ») | OWASP ASI06 | Pattern de persistance dans descriptions / contenus retournés | `poisoning::patterns` — catégorie `persistance_memoire` (Haute) | 1 correspondance | Outils de gestion de mémoire légitimes (serveurs memory MCP) décrivant leur fonction | 🔨 |
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
| Injection de commande par métacaractères shell (`;`, `&&`, pipe vers shell — règle Datadog) | Datadog SIEM | Métacaractères shell + binaire réseau dans un argument ou une description | `poisoning::patterns` — catégorie `injection_commande` (Critique) | 1 correspondance (les métacaractères sont rares dans les interactions MCP typiques) | Outils d'exécution shell légitimes documentant leur syntaxe — à allowlister par portée | 🔨 |
| Exposition de credentials dans les sorties d'outils (PoC Invariant `direct-poisoning.py`) | Datadog | Sortie d'outil contenant clés SSH, tokens, variables d'env | `inspecter_texte` (catégories `chemins_sensibles`, `lecture_exfiltration`) sur les sorties — en mémoire uniquement | 1 correspondance | Outils de diagnostic affichant des chemins | 🗓 (câblage monitor) |
| Connexion sortante post-lecture (process/socket) | MCP-24 | Lecture fichier sensible puis connexion réseau vers domaine hors baseline dans la même fenêtre | Capteur réseau au niveau process/socket | Fenêtre temporelle configurable | Télémétrie légitime du serveur | 🗓 (capteur réseau) |
| Aggregation Exfiltration (fragments non sensibles combinés) | MCP-24 | Volume cumulé de lectures multi-outils suivi d'une écriture externe | Extension du `DetecteurExfiltration` (compteur de lectures par session) | N lectures + 1 écriture externe | Agents de synthèse légitimes | 🗓 |

## 7. Chaîne d'approvisionnement des registres MCP

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Sosie / typosquat de serveur officiel | OWASP MCP09 | Similarité de nom+description avec un paquet officiel | `detect::lookalikes` — Jaro-Winkler asymétrique, 4 registres (PulseMCP, registre officiel, Smithery, mcp.so), allowlist des paquets officiels | Seuil de similarité ajusté par asymétrie | Forks légitimes (allowlist) | ✅ |
| Comportement post-install non documenté (cas Postmark BCC) | OWASP ASI04 | Connexion réseau non documentée déclenchée par une action bénigne | Combo exfiltration + baseline de portée (module 1.7 : « ce à quoi ça touche ») | Portée observée > portée déclarée | Mise à jour de fonctionnalité | ✅ partiel / 🗓 (capteur réseau pour le volet socket) |
| Paquet compromis (worms npm Shai-Hulud, registre ClawHub) | OWASP ASI04, CVE-2025-6514, CVE-2025-49596, CVE-2025-54136, CVE-2025-54994 | Hash de paquet divergent de la release publiée, version non épinglée | Vérification SBOM / intégrité binaire (module 3.9) + threat-intel feed (STIX/TAXII) | Hash hors release publiée = constat | Builds locaux non publiés | ✅ partiel |

## 8. Détournement des flux OAuth (serveurs MCP distants)

| Technique | Référence | Signal endpoint | Règle Sentinel | Seuil / logique | Faux positifs attendus | Statut |
|---|---|---|---|---|---|---|
| Token passthrough (anti-pattern interdit par la spec juin 2025) | Spec MCP Authorization | Token reçu du client retransmis tel quel vers un endpoint downstream | Observation du flux HTTP : même token sur deux segments distincts | 1 occurrence = **Critique** (rupture de la frontière d'audience RFC 9068) | Aucun cas légitime (interdit par la spec) | 🗓 (capteur HTTP étendu) |
| Confused deputy (client ID statique + dynamic client registration) | Spec MCP Authorization | Flux d'autorisation sans étape de consentement pour un client nouvellement enregistré | Observation du flux OAuth | Absence de consentement = constat | Consentement hors bande | 🗓 |
| Redirection vers un AS non baseline / replay de refresh token | SAFE-MCP (vol/replay de tokens OAuth) | `redirect_uri` divergent ; usage de refresh token après fin de session | Baseline des AS connus par serveur + corrélation sessions | 1 divergence = **Critique** | Rotation d'AS annoncée | 🗓 |
| Serveur distant sans authentification | OWASP A07 | Endpoint MCP accessible sans mécanisme d'auth | `TypeConstat::SansAuthentification` | Détection à la découverte | Serveurs locaux de dev | ✅ |

---

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

# Sentinel MCP — Orchestration des 50 agents développeurs

**Objet :** affectation de 10 développeurs par module (5 modules, 50 agents au total). Chaque agent a un contexte partagé, un rôle unique et non redondant dans son module, et des livrables précis.

**Date :** juin 2026

---

## Contexte global (à connaître par TOUS les agents)

Vous construisez **Sentinel MCP**, un outil de découverte et de surveillance des serveurs MCP (Model Context Protocol) que les agents IA d'une entreprise contactent. Le produit est un binaire unique auto-hébergé (Go ou Rust), read-only par défaut, déployable en moins de cinq minutes.

**Mission produit :** une entreprise lance le binaire, voit en cinq minutes des serveurs MCP qu'elle ignorait (dont au moins un à risque), constate qu'ils sont surveillés en continu, et obtient un rapport de conformité signé pour son auditeur.

**Le flux technique que vous servez :**
```
Trafic agents IA → [Capteur] → [Pipeline de scan] → [Store local] → [Interface]
```

**Règles d'ingénierie non négociables, valables pour tous :**
- Read-only par défaut : on observe, on ne bloque pas (pas d'enforcement en v1).
- Précision avant couverture : un faux positif en démo coûte une vente.
- Inspection en vol, jamais de stockage du contenu des arguments d'appel.
- Pipeline sans état : tout l'état vit dans le store.
- Tout reste sur la machine du client : aucun appel sortant hors module registre.
- Canonicalisation systématique de toute empreinte (JSON trié avant hash).

**Repères protocole :** MCP = JSON-RPC 2.0 en UTF-8, deux transports (stdio local et Streamable HTTP). Méthodes clés : `initialize`, `tools/list`, `tools/call`, `notifications/tools/list_changed`. La réponse `tools/list` (nom + description + `inputSchema` par outil) est la cible centrale du scan.

**Métrique de succès unique de tout le projet :** temps entre le lancement du binaire et l'apparition de la première carte rouge. Objectif : sous cinq minutes, sans configuration.

**Conventions inter-modules :**
- Le capteur émet des `EvenementBrut` normalisés ; les modules en aval consomment ce format.
- Le pipeline écrit des faits structurés dans le store ; l'interface les lit.
- Identifiants de conformité officiels : OWASP MCP09 (Shadow MCP), MCP03 (Tool Poisoning), SAFE-MCP SAFE-T1001 (poisoning) et SAFE-T1201 (rug-pull).

---

# MODULE 1 — SCAN (découverte de l'inventaire, gratuit, l'appât)

**Contexte du module :** produire l'inventaire et le « wow » en moins de cinq minutes, sans config, sans risque. C'est le module gratuit qui sert d'appât. Il contient le capteur et le détecteur de signature MCP, les deux composants dont dépend tout le reste.

### Agent 1.1 — Lead capteur stdio
**Contexte :** le transport stdio lance le serveur MCP en sous-processus et échange du JSON-RPC délimité par retours à la ligne sur stdin/stdout. Aucun point d'interception réseau, aucune auth de transport — c'est le cas le plus dur.
**Rôle :** concevoir et coder le wrapper qui enveloppe l'exécutable d'un serveur stdio, relaie stdin/stdout, et observe le trafic au passage sans le modifier.
**Livrables :** module de capture stdio, tests avec serveurs stdio de référence, doc d'intégration du wrapper.

### Agent 1.2 — Lead capteur HTTP
**Contexte :** le transport Streamable HTTP expose un endpoint unique (`/mcp`) acceptant POST et GET, avec session via en-tête `Mcp-Session-Id`, et réponses parfois en flux SSE.
**Rôle :** coder la capture du trafic HTTP en mode passif local (mode A), regrouper les messages par `Mcp-Session-Id`, gérer le cas SSE.
**Livrables :** module de capture HTTP local, regroupement par session, gestion SSE, tests.

### Agent 1.3 — Normalisateur d'événements
**Contexte :** stdio et HTTP produisent des flux hétérogènes ; le pipeline a besoin d'un format unique.
**Rôle :** définir et implémenter le format `EvenementBrut` (session_id, transport, serveur, direction, méthode, payload, horodatage) et la couche qui normalise les deux captures vers ce format.
**Livrables :** schéma `EvenementBrut`, normaliseur, contrat d'interface avec le pipeline.

### Agent 1.4 — Détecteur de signature MCP (filtre grossier)
**Contexte :** premier étage du pipeline, décide si un événement est du MCP. Détermine le taux de faux positifs global.
**Rôle :** coder le filtre rapide sur présence de `"jsonrpc": "2.0"`, optimisé pour écarter à coût quasi nul le trafic non pertinent.
**Livrables :** filtre grossier, benchmarks de débit, tests de non-régression sur trafic mixte.

### Agent 1.5 — Détecteur de signature MCP (confirmation)
**Contexte :** le filtre grossier ne suffit pas ; d'autres systèmes utilisent JSON-RPC. Il faut confirmer par les méthodes MCP ou l'appartenance à une session.
**Rôle :** coder la confirmation par méthode MCP connue + suivi des sessions ouvertes par `initialize`, pour ne pas rater les `tools/call` d'une session déjà identifiée.
**Livrables :** logique de confirmation, table des sessions actives, tests anti-faux-positifs.

### Agent 1.6 — Parseur de réponses `tools/list`
**Contexte :** la réponse `tools/list` est la cible centrale du scan ; chaque outil y a un nom, une description, un `inputSchema`.
**Rôle :** parser robustement ces réponses, extraire le tableau d'outils complet avec schéma imbriqué, gérer les variations et les réponses malformées.
**Livrables :** parseur d'outils, structure `Outil` typée, tests sur réponses réelles et tordues.

### Agent 1.7 — Détecteur de portée (« ce à quoi ça touche »)
**Contexte :** la classification de risque a besoin de savoir si un serveur touche au filesystem, à une base de données, à une API externe ou à des secrets.
**Rôle :** inférer la portée d'un serveur à partir des noms et descriptions d'outils (heuristiques : `read_file` → filesystem, `query` → DB, etc.).
**Livrables :** classifieur de portée, jeu d'heuristiques documenté, tests.

### Agent 1.8 — Performance et faux positifs
**Contexte :** « précision avant couverture » est la règle d'or ; la démo doit être propre.
**Rôle :** construire le banc de mesure du taux de faux positifs et du débit, et piloter l'objectif « faux positifs proche de zéro » sur l'ensemble du module scan.
**Livrables :** jeux de trafic de test (MCP réel + leurres JSON-RPC), tableau de bord de précision, rapport d'optimisation.

### Agent 1.9 — Contrat d'interface scan→store
**Contexte :** le scan alimente le store ; le contrat doit être stable pour que les modules avancent en parallèle.
**Rôle :** spécifier et figer l'API par laquelle le scan écrit serveurs et outils détectés, en coordination avec le module store.
**Livrables :** spec d'interface versionnée, mocks pour les autres modules, tests de contrat.

### Agent 1.10 — Intégrateur démo « scan qui se remplit »
**Contexte :** l'effet « ça travaille, ça trouve » est central pour le wow ; il faut un chemin de bout en bout dès tôt.
**Rôle :** assembler capteur + signature + parseur en un flux démontrable qui remplit progressivement l'inventaire, et tenir la métrique des cinq minutes.
**Livrables :** binaire de démo mode A, scénario de démo reproductible, mesure du time-to-first-red.

---

# MODULE 2 — SURVEILLANCE CONTINUE (observe en continu, payant, récurrent)

**Contexte du module :** transformer le scan ponctuel en observation permanente. C'est le premier module payant : un scan est une photo, la surveillance est une vidéo. Il gère les baselines, l'historique, et la détection de la dérive — y compris inter-session, qui est un trou ouvert sur le marché.

### Agent 2.1 — Lead surveillance continue
**Contexte :** le capteur reste actif et ré-empreinte chaque serveur à chaque contact.
**Rôle :** concevoir la boucle de surveillance permanente, son cycle de vie, et son orchestration avec le pipeline.
**Livrables :** moteur de surveillance, gestion du cycle de vie, doc d'architecture du module.

### Agent 2.2 — Gestion des baselines
**Contexte :** quand un opérateur approuve un serveur, on fige son empreinte ; toute la détection de rug-pull en dépend.
**Rôle :** implémenter la création, le stockage et la mise à jour des baselines d'empreinte, avec traçabilité (qui a approuvé, quand).
**Livrables :** logique de baseline, intégration au store, tests de cohérence.

### Agent 2.3 — Détection des nouveaux serveurs
**Contexte :** la surveillance doit signaler tout serveur apparu depuis le dernier état connu.
**Rôle :** coder la comparaison continue entre serveurs observés et serveurs déjà connus, et l'émission d'un fait « nouveau serveur ».
**Livrables :** détecteur de nouveauté, déduplication, tests.

### Agent 2.4 — Détection de changement intra-session
**Contexte :** dans une session, toute nouvelle réponse `tools/list` doit être comparée à la baseline.
**Rôle :** câbler la comparaison empreinte courante vs baseline au sein d'une session, déclenchée par `tools/list` ou par `notifications/tools/list_changed`.
**Livrables :** détecteur intra-session, gestion du cas « changement sans notification préalable », tests.

### Agent 2.5 — Détection de dérive inter-session (différenciateur)
**Contexte :** la dérive entre sessions reste un trou ouvert sur la majorité du marché ; c'est un avantage concurrentiel.
**Rôle :** implémenter la comparaison des empreintes d'une session à l'autre via baselines persistantes, et la détection de dérive lente.
**Livrables :** moteur de dérive inter-session, tests sur scénarios multi-sessions, note de positionnement concurrentiel.

### Agent 2.6 — Journal d'activité
**Contexte :** chaque contact (qui, quand, quels outils) est conservé ; c'est aussi la matière du rapport.
**Rôle :** coder l'enregistrement de l'historique des contacts par serveur (première/dernière vue, fréquence).
**Livrables :** journal de contacts, requêtes d'agrégation, tests.

### Agent 2.7 — Politique « changement légitime vs attaque »
**Contexte :** une mise à jour de version change l'empreinte sans être hostile ; la v1 alerte et laisse trancher, ne bloque pas.
**Rôle :** définir la politique de qualification d'un changement (alerter / ignorer / escalader) et l'exposer aux opérateurs.
**Livrables :** moteur de politique, états approuver/investiguer/bloquer, tests.

### Agent 2.8 — Confidentialité et rétention
**Contexte :** règle non négociable — inspection en vol, jamais de stockage des arguments d'appel.
**Rôle :** garantir et auditer que la surveillance ne persiste aucun contenu sensible, définir les durées de rétention.
**Livrables :** politique de rétention, contrôles automatiques anti-fuite, rapport de conformité interne.

### Agent 2.9 — Performance de la surveillance continue
**Contexte :** la surveillance tourne en permanence ; elle ne doit pas peser sur la machine du client.
**Rôle :** mesurer et optimiser l'empreinte CPU/mémoire de la boucle continue, gérer la montée en nombre de serveurs.
**Livrables :** benchmarks de charge, optimisations, seuils de ressources documentés.

### Agent 2.10 — Contrat surveillance↔détection↔alertes
**Contexte :** la surveillance alimente les modules 3 et 4 ; les contrats doivent être stables.
**Rôle :** spécifier les faits que la surveillance émet vers la détection (module 3) et les alertes (module 4).
**Livrables :** specs d'interface versionnées, mocks, tests de contrat.

---

# MODULE 3 — DÉTECTION RUG-PULL + SOSIES (le différenciateur technique)

**Contexte du module :** le différenciateur technique le plus impressionnant en démo. Couvre deux attaques que l'acheteur comprend instantanément : le rug-pull (serveur qui change après approbation, SAFE-T1201) et les sosies (serveurs usurpant une marque sur les registres). Inclut aussi l'inspection de poisoning (MCP03 / SAFE-T1001).

### Agent 3.1 — Lead empreinte canonique
**Contexte :** le point technique le plus important du produit. Sans canonicalisation, un réordonnancement de champs crée un faux positif.
**Rôle :** concevoir et coder la sérialisation JSON canonique (outils triés par nom, clés triées, encodage stable) appliquée avant tout hash.
**Livrables :** fonction de canonicalisation, suite de tests anti-faux-positifs sur réordonnancements, doc de référence.

### Agent 3.2 — Empreinte par outil et par serveur
**Contexte :** un SHA-256 par outil et un global par serveur, `inputSchema` complet inclus.
**Rôle :** implémenter le calcul d'empreintes individuelles et agrégées, intégrer la baseline du module 2.
**Livrables :** moteur d'empreinte, intégration baseline, tests.

### Agent 3.3 — Moteur de diff lisible
**Contexte :** toute alerte de rug-pull doit porter le diff exact entre baseline et version courante.
**Rôle :** coder le calcul et le rendu d'un diff lisible (description, paramètres, défauts, enums, imbriqué).
**Livrables :** moteur de diff, rendu structuré pour interface et rapport, tests.

### Agent 3.4 — Détecteur de rug-pull
**Contexte :** un serveur peut changer ses outils sans émettre `notifications/tools/list_changed` (cas suspect).
**Rôle :** orchestrer empreinte + comparaison + diff pour produire un constat de rug-pull, en gérant le cas du changement silencieux.
**Livrables :** détecteur de rug-pull, gestion du changement sans notification, tests sur serveurs piégés de référence.

### Agent 3.5 — Lead inspecteur de poisoning
**Contexte :** la description d'un outil est du texte libre lu par le modèle et contrôlable par l'attaquant ; elle peut contenir des instructions cachées.
**Rôle :** concevoir l'architecture de l'inspecteur de descriptions et son intégration au pipeline.
**Livrables :** architecture de l'inspecteur, contrat d'entrée/sortie, doc.

### Agent 3.6 — Bibliothèque de patterns de poisoning
**Contexte :** catégories à couvrir — instructions impératives au modèle, références à chemins sensibles (`.env`, `~/.ssh`, `/etc/passwd`), balises pseudo-système (`[SYSTEM]`), texte invisible/encodé.
**Rôle :** constituer et maintenir le jeu de patterns de détection, équilibré pour minimiser faux positifs et angles morts.
**Livrables :** bibliothèque de patterns versionnée, corpus de test (malveillant + bénin), métriques de précision/rappel.

### Agent 3.7 — Détecteur de combinaison exfiltration
**Contexte :** l'attaque réelle combine lecture de données sensibles via un serveur de confiance et écriture vers un canal externe — au niveau session, pas serveur isolé.
**Rôle :** coder la détection de la combinaison lecture-secret + écriture-externe sur une même session.
**Livrables :** détecteur transversal de session, tests sur scénario type Invariant Labs WhatsApp.

### Agent 3.8 — Lead détection de sosies (registres)
**Contexte :** jusqu'à 15 sosies par serveur officiel ; un sosie imite nom et description pour se faire installer.
**Rôle :** concevoir le connecteur aux registres publics (PulseMCP, registre officiel, Smithery, mcp.so) et l'architecture de détection (mode C).
**Livrables :** connecteur registres, architecture du module sosies, doc.

### Agent 3.9 — Similarité de marque et vérification SBOM
**Contexte :** détection par similarité de nom/description, plus vérification des hash de binaire et SBOM contre les releases publiées.
**Rôle :** coder l'algorithme de similarité (nom + description) et la vérification d'intégrité binaire/SBOM.
**Livrables :** moteur de similarité, vérificateur SBOM, alertes sur nouveau serveur publié au nom de l'organisation, tests.

### Agent 3.10 — Validation contre corpus d'attaques
**Contexte :** la crédibilité du module repose sur sa capacité à attraper les attaques connues sans crier au loup.
**Rôle :** maintenir un corpus d'attaques de référence (rug-pull, poisoning, sosies) et mesurer en continu la détection.
**Livrables :** corpus versionné, harnais de test automatisé, rapport de couverture mappé sur SAFE-MCP.

---

# MODULE 4 — ALERTES (ce qui rend la surveillance vivante)

**Contexte du module :** sans alerte, la surveillance est un journal que personne ne lit. L'alerte est ce qui fait que l'outil « parle » à l'acheteur entre deux audits. Règle absolue : toute alerte critique porte le diff ou la raison précise — une alerte sans contexte actionnable détruit la confiance autant qu'un faux positif.

### Agent 4.1 — Lead moteur d'alertes
**Contexte :** lit les nouveaux constats du store et décide quoi émettre.
**Rôle :** concevoir le moteur d'alertes, sa boucle de lecture des constats, son orchestration.
**Livrables :** moteur d'alertes, architecture, doc.

### Agent 4.2 — Matrice de sévérité
**Contexte :** chaque type d'événement a une sévérité (moyenne/haute/critique) définie dans la spec.
**Rôle :** implémenter le mapping événement→sévérité et le rendre configurable par l'opérateur.
**Livrables :** moteur de sévérité, configuration, tests.

### Agent 4.3 — Canal tableau de bord
**Contexte :** badge + flux d'événements dans l'interface.
**Rôle :** coder l'émission temps réel vers le tableau de bord (badge, flux), en coordination avec le module 5.
**Livrables :** canal dashboard, flux d'événements, tests.

### Agent 4.4 — Canal e-mail
**Contexte :** notification par e-mail pour les alertes hautes et critiques.
**Rôle :** implémenter l'envoi d'e-mails avec contenu actionnable (diff/raison inclus), gestion des échecs.
**Livrables :** canal e-mail, gabarits, file de retry, tests.

### Agent 4.5 — Canal webhook
**Contexte :** webhook générique + intégrations Slack et Teams.
**Rôle :** coder l'émission webhook (générique, Slack, Teams) avec charge utile structurée.
**Livrables :** canal webhook, connecteurs Slack/Teams, tests.

### Agent 4.6 — Enrichissement des alertes (diff/raison)
**Contexte :** règle absolue — une alerte critique porte toujours le diff ou la raison précise.
**Rôle :** garantir que chaque alerte est enrichie du contexte actionnable issu du module 3 (diff, pattern, raison).
**Livrables :** couche d'enrichissement, contrat avec le module 3, tests de complétude.

### Agent 4.7 — Déduplication et anti-bruit
**Contexte :** un flot d'alertes répétitives tue l'attention autant que les faux positifs.
**Rôle :** coder la déduplication, le regroupement et la limitation de fréquence des alertes.
**Livrables :** moteur anti-bruit, règles de regroupement, tests.

### Agent 4.8 — Cycle de vie des alertes
**Contexte :** une alerte passe par des états (ouverte/investiguée/résolue) liés aux constats.
**Rôle :** implémenter le suivi d'état des alertes et son lien avec les états de constats du module 2.
**Livrables :** machine à états, intégration store, tests.

### Agent 4.9 — Préparation SIEM (v2)
**Contexte :** la sortie SIEM est en v2 mais l'architecture doit l'anticiper.
**Rôle :** concevoir le contrat de sortie vers SIEM (format, structure) sans l'implémenter en v1, pour éviter une refonte.
**Livrables :** spec de sortie SIEM, point d'extension dans le moteur, doc.

### Agent 4.10 — Tests de bout en bout des alertes
**Contexte :** une alerte qui n'arrive pas ou arrive vide est un échec produit.
**Rôle :** construire les tests de bout en bout (constat → alerte → réception sur chaque canal) et mesurer la latence.
**Livrables :** suite de tests E2E multi-canaux, mesure de latence, rapport de fiabilité.

---

# MODULE 5 — RAPPORT SIGNÉ (preuve de conformité, ce qui déclenche le chèque)

**Contexte du module :** la détection impressionne, le rapport fait signer. Un acheteur ne paie pas pour voir ses serveurs, il paie pour prouver à son auditeur qu'il couvre MCP09 et MCP03. Le livrable est un bundle d'évidence horodaté et signé (PDF pour l'auditeur, JSON pour l'intégration). Ce module contient aussi le tableau de bord et l'inventaire approuvable.

### Agent 5.1 — Lead générateur de rapport
**Contexte :** orchestre la production du bundle complet à partir du store.
**Rôle :** concevoir le pipeline de génération de rapport et son orchestration.
**Livrables :** moteur de rapport, architecture, doc.

### Agent 5.2 — Résumé exécutif
**Contexte :** une page lisible par un non-technique (compte de serveurs, non approuvés, à risque).
**Rôle :** coder la génération du résumé exécutif à partir des agrégats du store.
**Livrables :** générateur de résumé, gabarit, tests.

### Agent 5.3 — Inventaire et journal des changements
**Contexte :** inventaire complet + journal horodaté des changements avec diffs (preuve que la surveillance tourne).
**Rôle :** coder la section inventaire et la section historique/diffs du rapport.
**Livrables :** générateurs de sections, intégration journal du module 2 et diffs du module 3, tests.

### Agent 5.4 — Moteur de mapping de conformité
**Contexte :** chaque constat relié à OWASP MCP09/MCP03, SAFE-MCP (T1001, T1201), et frameworks (SOC 2, ISO 27001). Un mapping faux est pire que pas de rapport.
**Rôle :** implémenter et maintenir le mapping constat→référentiel, et le tenir à jour avec l'évolution des standards (beta 2026).
**Livrables :** table de mapping versionnée, moteur d'application, validation par relecture experte OWASP.

### Agent 5.5 — Signature cryptographique et horodatage
**Contexte :** le bundle doit être horodaté et signé cryptographiquement pour être présentable tel quel à un auditeur.
**Rôle :** implémenter la signature du bundle et l'horodatage vérifiable.
**Livrables :** module de signature, vérificateur, doc de chaîne de confiance.

### Agent 5.6 — Rendu PDF
**Contexte :** le PDF circule en interne et justifie la dépense ; il doit avoir l'air sérieux dès la v1.
**Rôle :** coder le rendu PDF professionnel du rapport complet.
**Livrables :** moteur de rendu PDF, gabarit soigné, tests de rendu.

### Agent 5.7 — Export JSON
**Contexte :** le JSON sert à l'intégration côté client.
**Rôle :** coder l'export JSON structuré du bundle, stable et documenté.
**Livrables :** export JSON, schéma versionné, tests.

### Agent 5.8 — Tableau de bord d'inventaire
**Contexte :** une carte par serveur (nom, outils, portée, statut, couleur), remplissage progressif pendant le scan, filtres, détail par serveur avec diff.
**Rôle :** coder le tableau de bord et la vue de détail, en lisant le store en lecture seule.
**Livrables :** tableau de bord, vue détail, affichage des diffs, tests d'interface.

### Agent 5.9 — Flux d'approbation d'inventaire
**Contexte :** l'opérateur marque chaque serveur approuvé/à investiguer/à bloquer ; l'approbation fige la baseline (module 2).
**Rôle :** coder l'interface d'approbation et son câblage avec les baselines.
**Livrables :** flux d'approbation, intégration baseline, tests.

### Agent 5.10 — Plan de remédiation et intégration finale
**Contexte :** pour chaque serveur rouge, une action recommandée ; et l'ensemble doit s'assembler en un produit cohérent.
**Rôle :** générer le plan de remédiation et intégrer rapport + tableau de bord + approbation en un tout, valider la métrique des cinq minutes de bout en bout.
**Livrables :** générateur de plan de remédiation, intégration produit complète, validation du time-to-first-red de bout en bout.

---

## Coordination inter-modules

| Frontière | Côté émetteur | Côté récepteur | Agents responsables |
|---|---|---|---|
| Capteur → Pipeline | Module 1 (1.3, 1.9) | Module 1 (1.4) | 1.3, 1.9 |
| Scan → Store | Module 1 (1.9) | Store | 1.9 |
| Surveillance → Détection | Module 2 (2.10) | Module 3 (3.4) | 2.10, 3.4 |
| Surveillance → Alertes | Module 2 (2.10) | Module 4 (4.1) | 2.10, 4.1 |
| Détection → Alertes (diff) | Module 3 (3.3) | Module 4 (4.6) | 3.3, 4.6 |
| Détection → Rapport (diffs) | Module 3 (3.3) | Module 5 (5.3) | 3.3, 5.3 |
| Surveillance → Rapport (journal) | Module 2 (2.6) | Module 5 (5.3) | 2.6, 5.3 |
| Approbation → Baseline | Module 5 (5.9) | Module 2 (2.2) | 5.9, 2.2 |

Les agents « contrat » de chaque module (1.9, 2.10, 4.6, plus les leads) sont responsables de figer les interfaces tôt pour que les cinq modules avancent en parallèle sans se bloquer.

# Sentinel MCP — Lot de travail pour agent IA

Deux chantiers, dans cet ordre de priorité. Le premier réduit la friction
de test pour un acheteur (impact direct sur la vente). Le second muscle le
pitch « enterprise-ready » côté compliance / SIEM.

**Cible : macOS uniquement (Apple Silicon, Tauri 2). Ne pas porter
Windows/Linux. Ne pas toucher au cross-platform.**

Pile actuelle : 9 crates Rust en workspace, UI Tauri 2 + React 19, 42
commandes Tauri, persistance SQLite, signature Ed25519 des bundles d'audit
déjà en place. 487 tests passants (`cargo test --workspace`). Ne rien
casser de l'existant : tout ajout doit laisser la suite verte.

---

## Chantier 1 — Signature + notarisation Apple Developer ID (PRIORITÉ 1)

### Objectif

Produire un `.dmg` que n'importe qui peut installer en double-cliquant,
sans avertissement Gatekeeper, sans passer par le terminal. C'est la
condition pour qu'un acheteur non-développeur teste l'app seul.

État actuel : l'app n'est pas signée. À la première ouverture, macOS
affiche « développeur non identifié » et exige un contournement manuel
(clic droit > Ouvrir, ou `xattr -cr`). À supprimer entièrement.

Le compte Apple Developer (99 $/an) existe déjà. Un certificat
**Developer ID Application** est donc émettable.

### Pré-requis à vérifier / récupérer

1. Certificat **Developer ID Application** présent dans le trousseau
   (`security find-identity -v -p codesigning` doit le lister). S'il
   n'existe pas, le créer depuis le portail Apple Developer puis
   l'installer.
2. **Team ID** Apple (10 caractères, visible sur le portail). Sera
   injecté en variable d'environnement, jamais en dur dans le repo.
3. **App-specific password** généré sur appleid.apple.com (PAS le mot de
   passe du compte, PAS un token du portail developer). Sert à la
   notarisation via `notarytool`.

### Travail à réaliser

**1.1 — Configuration de signature Tauri**

Dans la configuration bundle macOS de Tauri (`tauri.conf.json` ou
équivalent selon la structure du projet) :

- renseigner l'identité de signature `Developer ID Application: <NOM> (<TEAM_ID>)`
- activer le **hardened runtime** (obligatoire pour la notarisation)
- pointer vers un fichier `entitlements.plist` (à créer, voir 1.2)

Ne PAS hardcoder le Team ID ni l'identité dans un fichier versionné si
possible : préférer une lecture depuis l'environnement au moment du build.

**1.2 — Fichier `entitlements.plist`**

Créer un `entitlements.plist` minimal compatible hardened runtime. Comme
Sentinel spawne des processus (le wrapper stdio qui lance les serveurs
MCP via npx/uvx), il faut autoriser ce qui est strictement nécessaire et
rien de plus. Entitlements à évaluer (activer uniquement ceux requis pour
que le spawn stdio et les appels réseau sortants fonctionnent sous
hardened runtime) :

- `com.apple.security.cs.allow-jit` — seulement si la WebView en a besoin
- `com.apple.security.cs.allow-unsigned-executable-memory` — à éviter si
  possible, n'activer que si le runtime le réclame
- `com.apple.security.cs.disable-library-validation` — nécessaire si des
  binaires tiers non signés Apple (node via npx) sont chargés dans le
  process ; à tester
- réseau client (sortant) pour les lookups registres, SMTP, webhook, SIEM

**Important** : commencer par le set le plus restrictif, builder, lancer,
observer les crashs hardened runtime, et n'ajouter un entitlement que
quand une fonctionnalité réelle casse sans lui. Documenter pourquoi chaque
entitlement est présent.

**1.3 — Notarisation + stapling**

- soumettre le `.dmg` (ou le `.app` zippé) à la notarisation Apple via
  `xcrun notarytool submit --wait`
- en cas de rejet, lire le log JSON de notarytool, corriger (souvent un
  binaire non signé profond dans le bundle, ou un entitlement manquant)
- une fois accepté, **stapler** le ticket : `xcrun stapler staple <chemin>`
- vérifier : `spctl -a -vvv -t install <App>.app` doit répondre
  `accepted` / `source=Notarized Developer ID`

**1.4 — Script de build reproductible**

Fournir un script unique (`scripts/build-signed.sh` ou équivalent) qui :

1. lit `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_PASSWORD` (app-specific),
   `SIGNING_IDENTITY` depuis l'environnement
2. build Tauri en release signé
3. notarise + attend
4. staple
5. vérifie via `spctl` et échoue bruyamment si la vérif ne passe pas
6. dépose le `.dmg` final dans un dossier `dist/` avec son nom de version

Le script ne doit JAMAIS écrire les secrets dans un fichier, un log, ou
le repo. Il les lit depuis l'env et c'est tout.

**1.5 — Documentation**

Un court `BUILD_SIGNING.md` expliquant : variables d'env requises, où
obtenir l'app-specific password, comment lancer le script, comment
vérifier le résultat. Destiné au futur propriétaire de l'app après vente.

### Critère d'acceptation chantier 1

Sur une machine macOS Apple Silicon vierge (autre que celle de build), le
`.dmg` se monte, l'app se glisse dans Applications, double-clic →
l'application s'ouvre **sans aucun avertissement Gatekeeper** et toutes
les fonctions live (discovery, probe stdio, scan, report) marchent. La
suite `cargo test --workspace` reste verte.

---

## Chantier 2 — Export STIX 2.1 + canal TAXII 2.1 (PRIORITÉ 2)

### Objectif

Permettre à Sentinel d'exporter ses constats (findings) et son threat
intel au format **STIX 2.1**, et de les pousser vers un serveur **TAXII
2.1** configuré par l'opérateur. C'est le format standard d'échange de
threat intelligence dans les SOC / outils GRC. Ça transforme le pitch
« outil dev » en « s'intègre dans une chaîne SecOps existante ».

Ça complète le canal SIEM existant (Splunk HEC / Elastic / Syslog) : le
SIEM reçoit des événements, STIX/TAXII fournit de l'intel structurée
interopérable.

### Périmètre STIX (ce qu'on produit)

Mapper les objets internes de Sentinel vers des **STIX Domain Objects**
(SDO) et des relations :

- chaque entrée du **threat intel feed** (les 17+ paquets connus) →
  objet `indicator` STIX, avec :
  - `pattern` STIX (ex. nom de paquet, hash d'empreinte si disponible)
  - `labels` / `indicator_types` dérivés des tags existants
    (`tool-poisoning`, `rug-pull`, `data-exfil`, `lookalike`,
    `account-compromise`, etc.)
  - `valid_from` = date de publication de l'entrée
  - références externes vers les IDs SAFE-T (T1001, T1201) en
    `external_references`
- chaque **finding critique/high** détecté localement → objet
  `observed-data` ou `indicator` selon le type, relié au serveur MCP
  concerné
- chaque **serveur MCP** audité → représentation en `software` /
  `infrastructure` (choisir le SDO le plus juste) pour pouvoir relier
  indicateur ↔ serveur via des `relationship`
- envelopper le tout dans un **STIX `bundle`** valide (id `bundle--<uuid>`,
  `spec_version` 2.1)

Contraintes :
- IDs STIX déterministes là où c'est possible (UUIDv5 sur une donnée
  stable) pour que deux exports du même état produisent les mêmes IDs
- timestamps en UTC RFC 3339
- le bundle doit valider contre le schéma STIX 2.1 (tester avec un
  validateur STIX dans les tests)

### Périmètre TAXII (comment on pousse)

Implémenter un **client** TAXII 2.1 (pas un serveur) :

- configuration opérateur dans Settings (nouvelle sous-section ou
  extension de la section SIEM) : URL racine de l'API TAXII, **collection
  ID** cible, authentification (Basic ou Bearer token)
- respecter les headers de contenu TAXII 2.1
  (`application/taxii+json;version=2.1`)
- endpoint d'ajout d'objets dans une collection : POST du bundle/des
  objets vers `.../collections/<id>/objects/`
- gérer la réponse `status` TAXII (succès partiel, objets rejetés)
- bouton **Send test** (comme pour email/webhook/SIEM) qui pousse un
  objet STIX de test vers la collection et rapporte le code de statut
- les secrets (token TAXII) persistés dans le fichier de support
  applicatif comme les autres canaux, **jamais loggés**, jamais en clair
  dans un endroit versionné

### Intégration UI

- **Settings** : nouvelle section « STIX / TAXII » (cohérente
  visuellement avec les sections Email / Webhook / SIEM existantes) :
  toggle Enable, URL API, Collection ID, auth, bouton Send test, bouton
  Save.
- **Page Report** : ajouter une action **Export STIX bundle** (à côté de
  Open PDF / Open JSON) qui écrit le bundle STIX 2.1 dans le dossier
  `reports/` et l'ouvre / révèle dans le Finder.
- Respecter le toggle **Outbound calls** existant : si l'opérateur a
  désactivé les appels sortants, le push TAXII est bloqué côté client
  avec un message clair (l'export STIX local en fichier reste autorisé,
  lui, puisqu'il ne sort pas de la machine).

### Commandes Tauri à ajouter

Sur le modèle des commandes existantes (`siem_test_send`,
`siem_save_config`, `siem_get_config`) :

- `stix_export_bundle` — génère le bundle STIX du state courant, écrit le
  fichier, renvoie le chemin
- `taxii_save_config` / `taxii_get_config` — persistance de la config
  canal
- `taxii_test_send` — pousse un objet de test, renvoie le statut HTTP/TAXII

Mettre à jour le compte de commandes dans la doc (38 → 42) et la
cartographie en annexe du FEATURES.md.

### Tests

- génération d'un bundle STIX 2.1 à partir d'un state de fixture, validé
  contre le schéma STIX 2.1
- déterminisme des IDs (UUIDv5) : deux exports du même state = mêmes IDs
- mapping tags internes → indicator_types STIX couvert pour chaque tag
- client TAXII : test du formatage de la requête (headers, content-type,
  corps) avec un serveur HTTP mock ; pas d'appel réseau réel en test
- respect du toggle Outbound calls (push bloqué quand désactivé)

### Critère d'acceptation chantier 2

Depuis la page Report, « Export STIX bundle » produit un fichier STIX 2.1
valide. Depuis Settings, une config TAXII renseignée + « Send test »
pousse un objet vers une collection TAXII et rapporte un statut. La suite
`cargo test --workspace` reste verte, et la doc commandes est à jour.

### Mise à jour documentaire

Une fois livré, retirer « Pas encore d'export STIX/TAXII (prévu en v0.3) »
de la section **Limites connues** du FEATURES.md, et ajouter STIX/TAXII
aux différenciateurs / canaux d'intégration.

---

## Règles transverses (les deux chantiers)

- macOS uniquement. Aucun code Windows/Linux.
- Ne rien casser : `cargo test --workspace` vert avant ET après.
- Read-only par défaut préservé : aucun de ces chantiers ne doit modifier
  une config client IA ni exécuter d'outil MCP.
- Aucun secret (certificat, app-specific password, token TAXII, token
  SIEM) écrit en clair dans le repo, un log, ou un fichier versionné. Tout
  passe par l'environnement ou le dossier de support applicatif protégé.
- Documenter chaque ajout pour le futur propriétaire de l'app : ces docs
  font partie de la valeur transmise à la vente.

# Build et signature de l'application

Document destiné au propriétaire de l'application. Décrit la procédure exacte pour produire un `.dmg` signé et notarisé pour macOS Apple Silicon.

## 1. Pré-requis

- Machine macOS sur Apple Silicon (arm64).
- Xcode Command Line Tools installés :
  ```
  xcode-select --install
  ```
- Node.js (LTS) et Rust stable installés (`rustup default stable`).
- Compte Apple Developer actif (99 USD/an).
- Certificat **Developer ID Application** installé dans le trousseau local. Vérification :
  ```
  security find-identity -v -p codesigning
  ```
  La sortie doit contenir une ligne du type :
  ```
  1) ABCDEF1234... "Developer ID Application: Nom Prénom (TEAMID12345)"
  ```
  Si le certificat est absent :
  1. Ouvrir Keychain Access → menu *Certificate Assistant* → *Request a Certificate From a Certificate Authority*. Renseigner l'email du compte Apple Developer, cocher *Saved to disk*. Cela produit un fichier `.certSigningRequest` (CSR).
  2. Aller sur https://developer.apple.com/account → Certificates, Identifiers & Profiles → Certificates → bouton `+` → choisir **Developer ID Application** → uploader le CSR.
  3. Télécharger le `.cer` généré, double-cliquer pour l'importer dans le trousseau *login*.

## 2. Variables d'environnement requises

| Variable          | Format / exemple                                              | Où l'obtenir                                                                                                                                                  |
|-------------------|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `APPLE_ID`        | `proprietaire@exemple.com`                                    | Email du compte Apple Developer.                                                                                                                              |
| `APPLE_TEAM_ID`   | 10 caractères alphanumériques, ex. `A1B2C3D4E5`               | https://developer.apple.com/account → *Membership details* → champ *Team ID*.                                                                                 |
| `APPLE_PASSWORD`  | App-specific password, format `xxxx-xxxx-xxxx-xxxx`           | https://appleid.apple.com → *Sign-In and Security* → *App-Specific Passwords* → *Generate*. **Ce n'est pas** le mot de passe du compte ni un token developer. |
| `SIGNING_IDENTITY`| `Developer ID Application: Nom Prénom (TEAMID12345)` (exact)  | Optionnel. Copier la chaîne entre guillemets retournée par `security find-identity -v -p codesigning`.                                                        |

## 3. Build

Depuis la racine du projet :

```
export APPLE_ID=proprietaire@exemple.com
export APPLE_TEAM_ID=A1B2C3D4E5
export APPLE_PASSWORD=xxxx-xxxx-xxxx-xxxx
./scripts/build-signed.sh
```

Le `.dmg` final est déposé dans `dist/`.

## 4. Vérification après build

Remplacer `<version>` par la version effective produite.

- Vérifier la signature et la notarisation :
  ```
  spctl -a -vvv -t install dist/Sentinel-<version>.dmg
  ```
  La sortie attendue contient `accepted` et `source=Notarized Developer ID`.

- Test fonctionnel : monter le `.dmg`, glisser l'app dans `/Applications`, double-cliquer. Aucun avertissement Gatekeeper ne doit s'afficher.

- Vérification additionnelle du staple :
  ```
  xcrun stapler validate dist/Sentinel-<version>.dmg
  ```

## 5. Dépannage

- **`errSecInternalComponent` pendant la signature** : trousseau verrouillé. Déverrouiller :
  ```
  security unlock-keychain ~/Library/Keychains/login.keychain-db
  ```

- **Notarisation rejetée** : récupérer le log détaillé via l'ID de soumission renvoyé par `notarytool` :
  ```
  xcrun notarytool log <submission-id> \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_PASSWORD"
  ```
  Chercher dans le JSON les messages `Code signature not valid` ou `binary requires entitlement`.

- **Binaire interne (sidecar) non signé** : re-signer manuellement avant ré-empaquetage :
  ```
  codesign --force --options runtime \
    --sign "$SIGNING_IDENTITY" \
    --entitlements sentinel/sentinel-desktop/src-tauri/entitlements.plist \
    <chemin/vers/binaire>
  ```

- **Lister toutes les soumissions notarisées récentes** :
  ```
  xcrun notarytool history --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_PASSWORD"
  ```

## 6. Sécurité

- Aucun secret ne doit être committé dans le dépôt. `APPLE_PASSWORD`, `APPLE_ID` et `APPLE_TEAM_ID` restent en variables d'environnement, ou dans un gestionnaire de secrets (1Password, Bitwarden), ou dans le trousseau macOS :
  ```
  security add-generic-password -a "$APPLE_ID" -s AC_PASSWORD -w xxxx-xxxx-xxxx-xxxx
  ```
  Récupération :
  ```
  security find-generic-password -a "$APPLE_ID" -s AC_PASSWORD -w
  ```

- Ne jamais committer :
  - les fichiers `.p12` (export du certificat avec clé privée),
  - les `.provisionprofile`,
  - le contenu de `~/Library/MobileDevice/*`,
  - les `.cer` privés ou les CSR.

- Vérifier que `.gitignore` couvre `dist/`, `*.p12`, `*.provisionprofile`, `*.cer`, et tout dossier de build local.

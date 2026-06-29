# Publier une release (et faire marcher `brew` / `curl install.sh` / l'Action)

Bonne nouvelle : le workflow `.github/workflows/release.yml` **construit déjà** tout ce qu'il faut.
Inutile d'ajouter `cargo-dist` (cf. `packaging/cargo-dist.md`, optionnel pour le wrapper npm).

## Ce que produit `release.yml` (sur tag `v*`)

- Job **`cli`** : compile `sentinel` pour les 5 cibles et empaquette
  `sentinel-<version>-<target>.tar.gz` + `.sha256`
  (`x86_64`/`aarch64`-`apple-darwin`, `x86_64`/`aarch64`-`unknown-linux-gnu`, `x86_64-pc-windows-msvc`).
- Job **`tauri`** : build l'app desktop signée/notarisée (nécessite les secrets Apple — voir `BUILD_SIGNING.md`).
- Job **`release`** : crée une **draft** GitHub Release avec tous les artefacts.

Ce nommage est exactement celui qu'attendent `docs/install.sh`, `action/action.yml` et la formule Homebrew.

## Étapes pour une release

```bash
# 1. Tag de version (déclenche release.yml)
git tag v0.8.0 && git push origin v0.8.0

# 2. Attendre la fin du workflow, puis PUBLIER la draft release dans l'UI GitHub
#    (ou : gh release edit v0.8.0 --draft=false)

# 3. Mettre à jour le tap Homebrew avec les vrais SHA-256 :
#    - automatique : si le secret HOMEBREW_TAP_TOKEN est configuré, le workflow
#      release-tap.yml le fait à la publication.
#    - manuel : scripts/release-tap.sh v0.8.0
```

Après ça, **tout marche** :

```bash
brew install MattJeff/sentinel/sentinel        # tap mis à jour
curl -fsSL https://sentinelmcp.dev/install.sh | sh
- uses: MattJeff/sentinelmcp/action@v1         # déjà fonctionnel
```

## Note importante : le job `tauri` peut bloquer la draft

`release` a `needs: [cli, tauri]`. Si les **secrets Apple** (notarisation) ne sont pas configurés, le job
`tauri` échoue → la draft n'est pas créée. Deux options :
- configurer les secrets Apple (voir `BUILD_SIGNING.md`) ;
- ou, pour une release **CLI-only**, retirer temporairement `tauri` de `needs:` dans `release.yml`.

## crates.io et npm (optionnel)

- `cargo install sentinel-cli` : publier le crate (`cargo publish -p sentinel-cli`, après avoir publié
  les crates de dépendance internes, ou activer Trusted Publishing OIDC).
- `npx sentinelmcp` : générer le wrapper npm via `cargo-dist` (voir `packaging/cargo-dist.md`).

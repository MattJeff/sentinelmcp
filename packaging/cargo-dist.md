# Distribution multi-canal avec `cargo-dist`

[`cargo-dist`](https://github.com/axodotdev/cargo-dist) (commande `dist`) génère, à chaque tag de release,
des **binaires multi-OS**, des **checksums**, des **installeurs** (shell/PowerShell), une **formule Homebrew**
et un **package npm** (`npx sentinelmcp`, zéro postinstall) — le tout publié sur les GitHub Releases.

C'est le flux recommandé : il garde Homebrew (`packaging/homebrew/sentinel.rb`) et le wrapper npm à jour
automatiquement, sans édition manuelle.

## Cibles publiées (alignées sur `action/action.yml`)

```
x86_64-apple-darwin      aarch64-apple-darwin
x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
x86_64-pc-windows-msvc
```
> Windows arm64 (`aarch64-pc-windows-msvc`) n'est pas publié — l'action le refuse explicitement.

## Mise en place (J0)

```bash
# 1. Installer l'outil
cargo install cargo-dist            # ou : curl --proto '=https' --tlsv1.2 -LsSf https://github.com/axodotdev/cargo-dist/releases/latest/download/cargo-dist-installer.sh | sh

# 2. Initialiser depuis la racine du workspace (sentinel/)
cd sentinel
dist init
#   - choisir l'installeur shell + powershell
#   - activer "homebrew" (tap = MattJeff/homebrew-sentinel)
#   - activer "npm" (package = sentinelmcp)
#   - cibles = les 5 ci-dessus
#   - le binaire publié est `sentinel` (bin du crate sentinel-cli)

# 3. cargo-dist écrit la config dans [workspace.metadata.dist] (Cargo.toml)
#    et un workflow .github/workflows/release.yml dédié.
#    ⚠️ Le repo a DÉJÀ un release.yml (build desktop signé/notarisé). Ne l'écrase pas :
#    fusionne, ou nomme le workflow cargo-dist `release-cli.yml`.
```

## Métadonnées requises (déjà en place / à vérifier)

- `sentinel-cli/Cargo.toml` : `description`, `repository`, `homepage`, `keywords`, `categories` ✅
- `[[bin]] name = "sentinel"` ✅
- `workspace.package.repository` = `https://github.com/MattJeff/sentinelmcp` ✅ (corrigé)
- Recommandé : ajouter `readme = "../../README.md"` et un `rust-version` (MSRV) au workspace.

## Publication

```bash
# Tag → le workflow cargo-dist construit tout et attache aux Releases
git tag v0.8.0 && git push origin v0.8.0

# crates.io (séparé de cargo-dist) :
#   activer Trusted Publishing (OIDC) sur crates.io, puis dans la CI : cargo publish -p sentinel-cli
#   (publier d'abord les crates de dépendance internes, ou utiliser `cargo publish --workspace` si dispo)
```

## npm wrapper

`cargo-dist` génère un package npm qui télécharge le bon binaire selon la plateforme **sans script postinstall**
(via `optionalDependencies` de packages par-cible). Résultat : `npx sentinelmcp scan` fonctionne partout.
Ne PAS écrire de wrapper npm à la main (les postinstall qui téléchargent un binaire sont une source classique
d'incidents de supply-chain — ironique pour un outil de sécurité).

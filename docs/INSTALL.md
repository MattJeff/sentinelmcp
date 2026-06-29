# Installation de Sentinel MCP (CLI)

Le binaire s'appelle `sentinel`. Les artefacts de release suivent le nommage
`sentinel-<version>-<target>.tar.gz`, chacun accompagne d'un fichier
`sentinel-<version>-<target>.tar.gz.sha256` pour la verification d'integrite.

Cibles publiees :

| OS      | Architecture | Target |
|---------|--------------|--------|
| macOS   | Apple Silicon | `aarch64-apple-darwin` |
| macOS   | Intel         | `x86_64-apple-darwin` |
| Linux   | x86_64        | `x86_64-unknown-linux-gnu` |
| Linux   | ARM64         | `aarch64-unknown-linux-gnu` |
| Windows | x86_64        | `x86_64-pc-windows-msvc` |

Sous Windows ARM64, aucun build natif n'est publie : l'installeur PowerShell
installe le binaire `x86_64-pc-windows-msvc`, execute via l'emulation x64 de
Windows 11.

## 1. Homebrew (macOS / Linux)

Le tap dedie `MattJeff/homebrew-sentinel` est publie : la voie classique
fonctionne directement et telecharge le binaire signe de la derniere release.

```sh
brew install MattJeff/sentinel/sentinel
```

Equivalent en deux temps :

```sh
brew tap MattJeff/sentinel
brew install sentinel
```

> Note : `brew install sentinelmcp` (sans le prefixe `MattJeff/sentinel/`) ne
> fonctionne pas — la formule n'est pas dans homebrew-core, uniquement dans le
> tap ci-dessus.

## 2. Installeur curl | bash (macOS / Linux)

```sh
curl -fsSL https://sentinelmcp.dev/install.sh | sh
```

L'installeur detecte l'OS et l'architecture, telecharge la derniere release,
verifie le checksum SHA-256 et installe dans `~/.local/bin` (ou
`/usr/local/bin` en repli).

Options via variables d'environnement :

```sh
# Installer une version precise
SENTINEL_VERSION=0.8.0 bash -c "$(curl -fsSL https://raw.githubusercontent.com/MattJeff/sentinelmcp/main/scripts/install.sh)"

# Choisir le dossier d'installation
SENTINEL_INSTALL_DIR=/opt/sentinel/bin bash -c "$(curl -fsSL https://raw.githubusercontent.com/MattJeff/sentinelmcp/main/scripts/install.sh)"
```

## 3. Installeur PowerShell (Windows)

```powershell
irm https://raw.githubusercontent.com/MattJeff/sentinelmcp/main/scripts/install.ps1 | iex
```

Installe dans `%LOCALAPPDATA%\Programs\sentinel` et ajoute ce dossier au PATH
utilisateur. Memes variables d'environnement : `SENTINEL_VERSION` et
`SENTINEL_INSTALL_DIR`.

## 4. cargo install

Avec une toolchain Rust installee (https://rustup.rs), directement depuis le
depot Git :

```sh
cargo install --git https://github.com/MattJeff/sentinelmcp sentinel-cli
```

> **Attention** : le projet n'est PAS publie sur crates.io. Le crate
> `sentinel-cli` qui y existe est un projet tiers sans rapport — n'executez
> pas `cargo install sentinel-cli` (sans `--git`), vous installeriez le
> binaire de quelqu'un d'autre.

## 5. Telechargement manuel

1. Ouvrir https://github.com/MattJeff/sentinelmcp/releases et telecharger
   l'archive correspondant a votre cible, par exemple :

   ```sh
   curl -fsSLO https://github.com/MattJeff/sentinelmcp/releases/download/v0.8.0/sentinel-0.8.0-aarch64-apple-darwin.tar.gz
   curl -fsSLO https://github.com/MattJeff/sentinelmcp/releases/download/v0.8.0/sentinel-0.8.0-aarch64-apple-darwin.tar.gz.sha256
   ```

2. Verifier le checksum :

   ```sh
   # macOS
   shasum -a 256 -c sentinel-0.8.0-aarch64-apple-darwin.tar.gz.sha256
   # Linux
   sha256sum -c sentinel-0.8.0-aarch64-apple-darwin.tar.gz.sha256
   ```

3. Extraire et installer :

   ```sh
   tar -xzf sentinel-0.8.0-aarch64-apple-darwin.tar.gz
   install -m 755 sentinel ~/.local/bin/sentinel
   ```

Sous Windows (PowerShell, `tar` est inclus depuis Windows 10) :

```powershell
Invoke-WebRequest https://github.com/MattJeff/sentinelmcp/releases/download/v0.8.0/sentinel-0.8.0-x86_64-pc-windows-msvc.tar.gz -OutFile sentinel.tar.gz
Invoke-WebRequest https://github.com/MattJeff/sentinelmcp/releases/download/v0.8.0/sentinel-0.8.0-x86_64-pc-windows-msvc.tar.gz.sha256 -OutFile sentinel.tar.gz.sha256

# Verification du checksum : compare le hash calcule au hash publie
$expected = ((Get-Content sentinel.tar.gz.sha256 -Raw).Trim() -split "\s+")[0]
$actual = (Get-FileHash sentinel.tar.gz -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "checksum invalide — archive corrompue ou compromise" }

tar -xzf sentinel.tar.gz
```

## 6. Build depuis les sources

```sh
git clone https://github.com/MattJeff/sentinelmcp.git
cd sentinelmcp/sentinel
cargo build --release -p sentinel-cli
./target/release/sentinel --help
```

## Verification

Quelle que soit la methode :

```sh
sentinel --help
```

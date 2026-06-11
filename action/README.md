# Sentinel MCP — GitHub Action

Audit statique des configurations MCP (Model Context Protocol) de votre dépôt,
directement en CI. L'action installe le CLI Sentinel depuis les GitHub
Releases, exécute `sentinel audit <path> --json`, publie un **Job Summary**
(tableau des constats), des **annotations** `::error` / `::warning` sur les
fichiers de config concernés, et fait échouer le job selon la sévérité.

Détections appliquées (sans probing réseau, conçu pour la CI) :

- **Poisoning** : instructions injectées dans les définitions de serveurs
  (args, variables d'env, descriptions) — exfiltration, prompt injection, etc.
- **Sosies / typosquats** : paquets imitant un paquet officiel
  (`@modelcontextprotocoll/server-fetch`…) ou deux identités suspectement
  proches dans le même inventaire.

Configs reconnues : `mcp.json`, `.mcp.json` (dont `.cursor/mcp.json`,
`.vscode/mcp.json`), `mcp_config.json`, `claude_desktop_config.json`.

## Usage minimal

```yaml
name: Sentinel MCP Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MattJeff/sentinelmcp/action@v0.3.0
```

> **Note sur les tags :** les exemples épinglent `@v0.3.0`, la cible prévue
> pour la première release de l'action — ce tag (comme `v1`) n'est **pas
> encore publié**. En attendant, utilisez
> `uses: MattJeff/sentinelmcp/action@main`, puis ré-épinglez sur `@v0.3.0`
> dès sa publication. Épingler une version précise (plutôt qu'un tag
> flottant comme `v1` ou `main`) est recommandé pour des builds
> reproductibles.

## Inputs

| Input     | Défaut   | Description                                                                                  |
|-----------|----------|----------------------------------------------------------------------------------------------|
| `path`    | `.`      | Dossier (ou fichier de config MCP) à auditer, relatif au workspace.                          |
| `version` | `latest` | Version du CLI Sentinel sans le « v » (ex. `0.3.0`), ou `latest` pour la dernière release.   |
| `fail-on` | `high`   | Sévérité minimale qui fait échouer le job : `critical` \| `high` \| `medium` \| `low` \| `never`. |

## Outputs

| Output      | Description                                                                  |
|-------------|------------------------------------------------------------------------------|
| `constats`  | Nombre total de constats remontés par l'audit.                               |
| `exit-code` | Code de sortie brut du CLI (`0` = ok, `1` = constats haute/critique, `2` = erreur). |
| `json`      | Chemin du rapport JSON brut (`sentinel audit --json`).                       |

## Sévérités et seuil `fail-on`

Le CLI remonte des constats en sévérité `info`, `moyenne`, `haute` ou
`critique`. Correspondance avec `fail-on` :

| `fail-on`  | Le job échoue si…                                  |
|------------|-----------------------------------------------------|
| `critical` | au moins un constat `critique`                      |
| `high`     | au moins un constat `haute` ou `critique` (défaut)  |
| `medium`   | au moins un constat `moyenne` ou plus               |
| `low`      | au moins un constat, quelle que soit la sévérité    |
| `never`    | jamais (rapport seul ; une erreur du CLI échoue toujours) |

Les constats `haute`/`critique` produisent des annotations `::error`, les
autres des `::warning`. Une erreur d'exécution du CLI (code `2`) fait toujours
échouer le job, quel que soit `fail-on`.

## Exemples

### Auditer un sous-dossier, épingler la version

```yaml
- uses: MattJeff/sentinelmcp/action@v0.3.0
  with:
    path: apps/agent
    version: '0.3.0'
    fail-on: critical
```

### Mode rapport seul (n'échoue jamais) + upload du JSON

```yaml
- uses: MattJeff/sentinelmcp/action@v0.3.0
  id: sentinel
  with:
    fail-on: never

- uses: actions/upload-artifact@v4
  with:
    name: sentinel-audit
    path: ${{ steps.sentinel.outputs.json }}
```

### Bloquer les PR qui touchent une config MCP

```yaml
name: Sentinel MCP Audit

on:
  pull_request:
    paths:
      - '**/mcp.json'
      - '**/.mcp.json'
      - '**/mcp_config.json'
      - '**/claude_desktop_config.json'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MattJeff/sentinelmcp/action@v0.3.0
        with:
          fail-on: high
```

### Matrice multi-OS

L'action supporte les runners Linux (x86_64 et arm64), macOS (x86_64 et
arm64) et Windows **x86_64 uniquement**. Windows arm64 n'est pas supporté :
aucun binaire `aarch64-pc-windows-msvc` n'est publié dans les releases, et
l'action échoue alors immédiatement avec un message explicite.

```yaml
jobs:
  audit:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: MattJeff/sentinelmcp/action@v0.3.0
```

## Hook pre-commit

Le dépôt expose aussi un hook [pre-commit](https://pre-commit.com) qui audite
les configs MCP modifiées avant chaque commit :

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/MattJeff/sentinelmcp
    rev: v0.3.0  # tag à venir — en attendant, épinglez un SHA de commit
    hooks:
      - id: sentinel-audit
```

Prérequis : le CLI `sentinel` doit être installé localement (le hook affiche
un message d'aide s'il est absent du PATH) :

```bash
curl -fsSL https://raw.githubusercontent.com/MattJeff/sentinelmcp/main/scripts/install.sh | bash
# ou
cargo install sentinel-cli
```

## Contrat du CLI

L'action s'appuie sur `sentinel audit <chemin> --json` :

- code de sortie `0` : aucun constat haute/critique ;
- code de sortie `1` : au moins un constat `haute` ou `critique` ;
- code de sortie `2` : erreur d'exécution (chemin introuvable, etc.) ;
- sortie JSON : `{ chemin, configs_trouvees[], serveurs[], constats[] }` où
  chaque constat porte `config`, `serveur`, `type` (`poisoning` | `sosie`),
  `severite` (`info` | `moyenne` | `haute` | `critique`), `titre`, `detail`.

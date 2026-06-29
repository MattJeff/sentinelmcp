#!/usr/bin/env bash
#
# publish-crates.sh — Publie les 12 crates Sentinel MCP sur crates.io dans
# l'ordre topologique (un crate n'est publié qu'après ses dépendances internes).
#
# PRÉREQUIS — s'authentifier UNE fois avant de lancer ce script :
#
#   cargo login <TOKEN_CRATES_IO>
#
# (Récupérer le token sur https://crates.io/me — il n'est PAS stocké ici.)
#
# Le script :
#   - publie chaque crate avec `cargo publish -p <crate>` ;
#   - attend entre chaque publication, le temps que crates.io indexe le crate
#     fraîchement publié (sinon le crate suivant ne trouve pas sa dépendance) ;
#   - s'arrête à la PREMIÈRE erreur (set -e).
#
# Idempotence : un crate déjà publié dans cette version fait échouer
# `cargo publish` (« crate version already uploaded »). Pour reprendre après
# coup, commenter les crates déjà publiés ou repartir du dernier en échec.
#
# Usage :
#   ./scripts/publish-crates.sh            # publie pour de vrai
#   DRY_RUN=1 ./scripts/publish-crates.sh  # répétition à blanc (--dry-run)

set -euo pipefail

# Racine du workspace Cargo (dossier parent de scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$SCRIPT_DIR/../sentinel"

# Délai d'indexation crates.io entre deux publications (en secondes).
SLEEP_BETWEEN="${SLEEP_BETWEEN:-30}"

# Ordre topologique : protocol en premier, cli en dernier.
# Chaque crate apparaît APRÈS toutes ses dépendances internes.
CRATES=(
  sentinel-protocol   # aucune dépendance interne
  sentinel-taxii      # aucune dépendance interne (client TAXII autonome)
  sentinel-store      # -> protocol
  sentinel-detect     # -> protocol, store
  sentinel-alerts     # -> protocol, store
  sentinel-scan       # -> protocol, store, detect
  sentinel-report     # -> protocol, store, detect, alerts
  sentinel-monitor    # -> protocol, store, detect, report
  sentinel-discovery  # -> protocol, store, detect, scan
  sentinel-stix       # -> protocol, store, discovery
  sentinel-guard      # -> protocol, store, detect, scan
  sentinel-cli        # -> protocol, store, detect, scan, monitor, alerts, report, discovery
)

DRY_RUN_FLAG=""
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  DRY_RUN_FLAG="--dry-run"
  echo ">> Mode DRY-RUN : aucune publication réelle."
fi

cd "$WORKSPACE_DIR"

total="${#CRATES[@]}"
i=0
for crate in "${CRATES[@]}"; do
  i=$((i + 1))
  echo ""
  echo "==================================================================="
  echo ">> [$i/$total] cargo publish -p $crate $DRY_RUN_FLAG"
  echo "==================================================================="
  cargo publish -p "$crate" $DRY_RUN_FLAG

  # Pas d'attente après le dernier crate.
  if [[ "$i" -lt "$total" && -z "$DRY_RUN_FLAG" ]]; then
    echo ">> Attente ${SLEEP_BETWEEN}s (indexation crates.io)…"
    sleep "$SLEEP_BETWEEN"
  fi
done

echo ""
echo ">> Terminé : $total crates traités."

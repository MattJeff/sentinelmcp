#!/usr/bin/env bash
#
# make-dmg.sh — Build, sign, notarize, staple and verify the Sentinel MCP
# macOS .dmg WITHOUT tauri's bundle_dmg.sh.
#
# Pourquoi : bundle_dmg.sh monte l'image et la met en forme via AppleScript,
# puis échoue au démontage (« Ressource occupée » — Spotlight/Finder retiennent
# le volume). Ici le .dmg est créé directement avec `hdiutil create -srcfolder`
# sur un dossier de staging (app + lien /Applications) : aucun montage, aucun
# AppleScript, aucun démontage.
#
# Secrets : AUCUN secret en variable d'environnement. La notarisation passe
# par le profil trousseau créé une fois pour toutes avec :
#   xcrun notarytool store-credentials sentinel --apple-id <email> --team-id <team>
#
# Variables optionnelles :
#   APPLE_SIGNING_IDENTITY — hash SHA-1 ou nom du certificat. Si absent,
#       auto-détection du premier « Developer ID Application » du trousseau,
#       par HASH (le trousseau peut contenir des doublons de nom → codesign
#       refuse le nom comme ambigu).
#   NOTARY_PROFILE — nom du profil notarytool (défaut : sentinel).
#   SKIP_NOTARIZE=1 — signe sans notariser (build local rapide).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DESKTOP_DIR="${PROJECT_ROOT}/sentinel/sentinel-desktop"
TAURI_DIR="${DESKTOP_DIR}/src-tauri"
BUNDLE_DIR="${TAURI_DIR}/target/release/bundle"
DIST_DIR="${PROJECT_ROOT}/dist"
NOTARY_PROFILE="${NOTARY_PROFILE:-sentinel}"

# ---------------------------------------------------------------------------
echo "==> [1/7] Identité de signature"
if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  APPLE_SIGNING_IDENTITY="$(
    security find-identity -v -p codesigning \
      | grep "Developer ID Application" \
      | head -n 1 \
      | awk '{print $2}'
  )"
  [[ -n "${APPLE_SIGNING_IDENTITY}" ]] || {
    echo "ERROR: aucun certificat 'Developer ID Application' dans le trousseau." >&2
    exit 1
  }
fi
export APPLE_SIGNING_IDENTITY
echo "    Identité : ${APPLE_SIGNING_IDENTITY}"

# ---------------------------------------------------------------------------
echo "==> [2/7] Build Tauri release (.app uniquement, signé)"
cd "${DESKTOP_DIR}"
pnpm tauri build --bundles app

APP="${BUNDLE_DIR}/macos/Sentinel MCP.app"
[[ -d "${APP}" ]] || { echo "ERROR: .app introuvable : ${APP}" >&2; exit 1; }

VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "${TAURI_DIR}/tauri.conf.json")"
DMG="${BUNDLE_DIR}/dmg/Sentinel MCP_${VERSION}_aarch64.dmg"
echo "    Version : ${VERSION}"

# ---------------------------------------------------------------------------
echo "==> [3/7] Création du .dmg (hdiutil create, sans montage)"
STAGE="$(mktemp -d -t sentinel-dmg-stage.XXXXXX)"
trap 'rm -rf "${STAGE}"' EXIT
cp -R "${APP}" "${STAGE}/"
ln -s /Applications "${STAGE}/Applications"

mkdir -p "${BUNDLE_DIR}/dmg"
rm -f "${DMG}"
hdiutil create -volname "Sentinel MCP" -srcfolder "${STAGE}" -ov -format UDZO -quiet "${DMG}"
echo "    DMG : ${DMG}"

# ---------------------------------------------------------------------------
echo "==> [4/7] Signature du .dmg"
codesign --force --sign "${APPLE_SIGNING_IDENTITY}" "${DMG}"

# ---------------------------------------------------------------------------
if [[ "${SKIP_NOTARIZE:-0}" == "1" ]]; then
  echo "==> [5/7] Notarisation SKIPPÉE (SKIP_NOTARIZE=1)"
else
  echo "==> [5/7] Notarisation (notarytool --keychain-profile ${NOTARY_PROFILE})"
  STATUS="$(
    xcrun notarytool submit "${DMG}" \
      --keychain-profile "${NOTARY_PROFILE}" \
      --wait --output-format json \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))'
  )"
  echo "    Statut : ${STATUS}"
  [[ "${STATUS}" == "Accepted" ]] || { echo "ERROR: notarisation refusée (${STATUS})." >&2; exit 1; }

  echo "==> [6/7] Stapling + vérification Gatekeeper"
  xcrun stapler staple "${DMG}"
  spctl -a -vvv -t install "${DMG}"
fi

# ---------------------------------------------------------------------------
echo "==> [7/7] Copie dans dist/"
mkdir -p "${DIST_DIR}"
FINAL="${DIST_DIR}/Sentinel-${VERSION}.dmg"
cp -f "${DMG}" "${FINAL}"
echo "==> OK : ${FINAL}"

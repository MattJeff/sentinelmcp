#!/usr/bin/env bash
#
# build-signed.sh — Build, sign, notarize, staple and verify the Sentinel MCP
# Tauri macOS .dmg in one shot.
#
# Required environment variables:
#   APPLE_ID          — Apple ID (email) used for notarytool
#   APPLE_TEAM_ID     — 10-char Apple Developer Team ID
#   APPLE_PASSWORD    — App-specific password for the Apple ID
#
# Optional environment variables:
#   SIGNING_IDENTITY  — Full codesign identity string. If unset, the script
#                       auto-detects a "Developer ID Application: ... ($APPLE_TEAM_ID)"
#                       identity from the user's keychain via `security find-identity`.
#
# IMPORTANT: This script never logs secret values. Do not add `set -x` and do
# not echo $APPLE_PASSWORD anywhere.

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve project paths (absolute, regardless of caller's cwd).
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DESKTOP_DIR="${PROJECT_ROOT}/sentinel/sentinel-desktop"
TAURI_DIR="${DESKTOP_DIR}/src-tauri"
DIST_DIR="${PROJECT_ROOT}/dist"

# ---------------------------------------------------------------------------
# [étape 0] Validate required environment variables (fail fast).
# ---------------------------------------------------------------------------
echo "==> [étape 0] Validation des variables d'environnement"

: "${APPLE_ID:?APPLE_ID is required (Apple ID email used for notarization)}"
: "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required (10-char Apple Developer Team ID)}"
: "${APPLE_PASSWORD:?APPLE_PASSWORD is required (app-specific password)}"

# Soft validation of formats (does not print the secret value).
if [[ ! "${APPLE_TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]]; then
  echo "ERROR: APPLE_TEAM_ID must be a 10-character alphanumeric Team ID." >&2
  exit 1
fi

if [[ -z "${APPLE_PASSWORD// }" ]]; then
  echo "ERROR: APPLE_PASSWORD is empty after trimming." >&2
  exit 1
fi

echo "    APPLE_ID      = ${APPLE_ID}"
echo "    APPLE_TEAM_ID = ${APPLE_TEAM_ID}"
echo "    APPLE_PASSWORD = (hidden, ${#APPLE_PASSWORD} chars)"

# ---------------------------------------------------------------------------
# [étape 1] Resolve the codesign identity.
# ---------------------------------------------------------------------------
echo "==> [étape 1] Résolution de l'identité de signature"

if [[ -z "${SIGNING_IDENTITY:-}" ]]; then
  # Auto-detect a Developer ID Application identity matching the team id.
  # `security find-identity` output looks like:
  #   1) ABCDEF1234 "Developer ID Application: Acme Corp (TEAMID1234)"
  DETECTED_IDENTITY="$(
    security find-identity -v -p codesigning 2>/dev/null \
      | grep "Developer ID Application" \
      | grep "(${APPLE_TEAM_ID})" \
      | head -n 1 \
      | sed -E 's/.*"(Developer ID Application:[^"]+)".*/\1/' \
      || true
  )"

  if [[ -z "${DETECTED_IDENTITY}" ]]; then
    echo "ERROR: No 'Developer ID Application: ... (${APPLE_TEAM_ID})' identity found in the keychain." >&2
    echo "       Set SIGNING_IDENTITY explicitly or import the certificate." >&2
    exit 1
  fi

  SIGNING_IDENTITY="${DETECTED_IDENTITY}"
  echo "    Identité détectée : ${SIGNING_IDENTITY}"
else
  echo "    Identité fournie  : ${SIGNING_IDENTITY}"
fi

export APPLE_SIGNING_IDENTITY="${SIGNING_IDENTITY}"
# Tauri / cargo-bundle also consult these:
export APPLE_ID
export APPLE_TEAM_ID
export APPLE_PASSWORD

# ---------------------------------------------------------------------------
# [étape 2] Move into the Tauri desktop project.
# ---------------------------------------------------------------------------
echo "==> [étape 2] cd ${DESKTOP_DIR}"
cd "${DESKTOP_DIR}"

# ---------------------------------------------------------------------------
# [étape 3] Install node dependencies if needed.
# ---------------------------------------------------------------------------
echo "==> [étape 3] Installation des dépendances npm"
if [[ ! -d "node_modules" ]]; then
  npm ci
else
  echo "    node_modules présent — skip npm ci"
fi

# ---------------------------------------------------------------------------
# [étape 4] Build the Tauri app in release mode (signs via tauri config).
# ---------------------------------------------------------------------------
echo "==> [étape 4] Build Tauri release (cargo build --release + signature)"
npm run tauri build

# ---------------------------------------------------------------------------
# [étape 5] Locate the produced .dmg.
# ---------------------------------------------------------------------------
echo "==> [étape 5] Localisation du .dmg produit"
DMG_DIR="${TAURI_DIR}/target/release/bundle/dmg"

if [[ ! -d "${DMG_DIR}" ]]; then
  echo "ERROR: DMG output directory not found: ${DMG_DIR}" >&2
  exit 1
fi

# Pick the most recently modified .dmg in the bundle output.
DMG="$(/bin/ls -1t "${DMG_DIR}"/*.dmg 2>/dev/null | head -n 1 || true)"
if [[ -z "${DMG}" || ! -f "${DMG}" ]]; then
  echo "ERROR: No .dmg file found under ${DMG_DIR}" >&2
  exit 1
fi
echo "    DMG : ${DMG}"

# ---------------------------------------------------------------------------
# [étape 6] Notarization via notarytool.
# ---------------------------------------------------------------------------
echo "==> [étape 6] Notarisation Apple (notarytool submit --wait)"
NOTARY_JSON="$(mktemp -t notary-result.XXXXXX.json)"
trap 'rm -f "${NOTARY_JSON}"' EXIT

# Submit. We capture stdout (JSON); stderr passes through to the console.
# We intentionally do NOT enable `set -x` and do NOT echo the password.
if ! xcrun notarytool submit "${DMG}" \
      --apple-id "${APPLE_ID}" \
      --team-id "${APPLE_TEAM_ID}" \
      --password "${APPLE_PASSWORD}" \
      --wait \
      --output-format json \
      > "${NOTARY_JSON}"; then
  echo "ERROR: notarytool submit failed." >&2
  cat "${NOTARY_JSON}" >&2 || true
  exit 1
fi

# Parse the JSON result (id, status). Use python3 for portable JSON parsing.
NOTARY_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("id",""))' "${NOTARY_JSON}")"
NOTARY_STATUS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "${NOTARY_JSON}")"

echo "    Submission id : ${NOTARY_ID}"
echo "    Status        : ${NOTARY_STATUS}"

if [[ "${NOTARY_STATUS}" != "Accepted" ]]; then
  echo "ERROR: Notarization status is '${NOTARY_STATUS}' (expected 'Accepted')." >&2
  if [[ -n "${NOTARY_ID}" ]]; then
    echo "---- notarytool log ----" >&2
    xcrun notarytool log "${NOTARY_ID}" \
      --apple-id "${APPLE_ID}" \
      --team-id "${APPLE_TEAM_ID}" \
      --password "${APPLE_PASSWORD}" >&2 || true
    echo "------------------------" >&2
  fi
  exit 1
fi

# ---------------------------------------------------------------------------
# [étape 7] Staple the ticket onto the .dmg.
# ---------------------------------------------------------------------------
echo "==> [étape 7] Stapling du ticket de notarisation"
if ! xcrun stapler staple "${DMG}"; then
  echo "ERROR: stapler staple failed for ${DMG}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# [étape 8] Gatekeeper / spctl verification.
# ---------------------------------------------------------------------------
echo "==> [étape 8] Vérification Gatekeeper (spctl)"
SPCTL_OUT="$(mktemp -t spctl.XXXXXX.log)"
trap 'rm -f "${NOTARY_JSON}" "${SPCTL_OUT}"' EXIT

# 8a. Verify the DMG (installer assessment).
if ! spctl -a -vvv -t install "${DMG}" > "${SPCTL_OUT}" 2>&1; then
  echo "ERROR: spctl assessment of the .dmg failed:" >&2
  cat "${SPCTL_OUT}" >&2
  exit 1
fi
cat "${SPCTL_OUT}"

if ! grep -q "accepted" "${SPCTL_OUT}" \
   || ! grep -q "source=Notarized Developer ID" "${SPCTL_OUT}"; then
  echo "ERROR: spctl did not report 'accepted' / 'source=Notarized Developer ID' for the .dmg." >&2
  exit 1
fi

# 8b. Verify the embedded .app by mounting the DMG read-only.
echo "    Vérification de l'application embarquée…"
MOUNT_DIR="$(mktemp -d -t sentinel-dmg-mount.XXXXXX)"
HDIUTIL_INFO="$(mktemp -t hdiutil.XXXXXX.plist)"
trap 'rm -f "${NOTARY_JSON}" "${SPCTL_OUT}" "${HDIUTIL_INFO}"; [ -d "${MOUNT_DIR}" ] && hdiutil detach "${MOUNT_DIR}" -quiet 2>/dev/null; rmdir "${MOUNT_DIR}" 2>/dev/null || true' EXIT

if ! hdiutil attach "${DMG}" -nobrowse -readonly -mountpoint "${MOUNT_DIR}" -plist > "${HDIUTIL_INFO}"; then
  echo "ERROR: hdiutil attach failed for ${DMG}" >&2
  exit 1
fi

APP_PATH="$(/usr/bin/find "${MOUNT_DIR}" -maxdepth 2 -name '*.app' -print -quit || true)"
if [[ -z "${APP_PATH}" ]]; then
  echo "ERROR: No .app bundle found inside the mounted DMG (${MOUNT_DIR})." >&2
  hdiutil detach "${MOUNT_DIR}" -quiet || true
  exit 1
fi
echo "    App : ${APP_PATH}"

SPCTL_APP_OUT="$(mktemp -t spctl-app.XXXXXX.log)"
if ! spctl --assess --type execute -vvv "${APP_PATH}" > "${SPCTL_APP_OUT}" 2>&1; then
  echo "ERROR: spctl assessment of the .app failed:" >&2
  cat "${SPCTL_APP_OUT}" >&2
  rm -f "${SPCTL_APP_OUT}"
  hdiutil detach "${MOUNT_DIR}" -quiet || true
  exit 1
fi
cat "${SPCTL_APP_OUT}"

if ! grep -q "accepted" "${SPCTL_APP_OUT}" \
   || ! grep -q "source=Notarized Developer ID" "${SPCTL_APP_OUT}"; then
  echo "ERROR: spctl did not report 'accepted' / 'source=Notarized Developer ID' for the .app." >&2
  rm -f "${SPCTL_APP_OUT}"
  hdiutil detach "${MOUNT_DIR}" -quiet || true
  exit 1
fi
rm -f "${SPCTL_APP_OUT}"

hdiutil detach "${MOUNT_DIR}" -quiet || true

# ---------------------------------------------------------------------------
# [étape 9] Copy the final DMG into dist/ with version-suffixed name.
# ---------------------------------------------------------------------------
echo "==> [étape 9] Copie du .dmg final dans dist/"

# Read version from tauri.conf.json first, fall back to Cargo.toml.
VERSION="$(
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version",""))' \
    "${TAURI_DIR}/tauri.conf.json" 2>/dev/null || true
)"

if [[ -z "${VERSION}" ]]; then
  VERSION="$(
    grep -E '^version[[:space:]]*=' "${TAURI_DIR}/Cargo.toml" \
      | head -n 1 \
      | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/'
  )"
fi

if [[ -z "${VERSION}" ]]; then
  echo "ERROR: Could not determine the application version." >&2
  exit 1
fi
echo "    Version : ${VERSION}"

mkdir -p "${DIST_DIR}"
FINAL_DMG="${DIST_DIR}/Sentinel-${VERSION}.dmg"
cp -f "${DMG}" "${FINAL_DMG}"
echo "    Copié vers : ${FINAL_DMG}"

echo "==> Build signé + notarisé + staplé + vérifié OK"
echo "    Artefact final : ${FINAL_DMG}"

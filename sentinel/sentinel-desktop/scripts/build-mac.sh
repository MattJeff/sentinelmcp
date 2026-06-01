#!/usr/bin/env bash
# Build the Sentinel MCP macOS app + DMG bundle via Tauri.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

echo "==> Working directory: ${PROJECT_DIR}"

# 1. Install JS deps (frozen if a lockfile exists, otherwise loose).
if [[ -f "pnpm-lock.yaml" ]]; then
  echo "==> pnpm install --frozen-lockfile"
  pnpm install --frozen-lockfile
else
  echo "==> pnpm install"
  pnpm install
fi

# 2. Build the frontend (vite -> dist/).
echo "==> pnpm build (frontend)"
pnpm build

# 3. Build the Tauri bundles: .app + .dmg.
echo "==> cargo tauri build --bundles app,dmg"
cargo tauri build --bundles app,dmg

# 4. Locate the produced DMG and report size + checksum.
DMG_DIR="${PROJECT_DIR}/src-tauri/target/release/bundle/dmg"
DMG_PATH="$(find "${DMG_DIR}" -maxdepth 1 -type f -name '*.dmg' | head -n 1)"

if [[ -z "${DMG_PATH}" || ! -f "${DMG_PATH}" ]]; then
  echo "ERROR: no .dmg produced under ${DMG_DIR}" >&2
  exit 1
fi

echo ""
echo "==> Build artefact"
echo "Path     : ${DMG_PATH}"
echo "Size     : $(du -h "${DMG_PATH}" | awk '{print $1}')"
echo "SHA-256  : $(shasum -a 256 "${DMG_PATH}" | awk '{print $1}')"

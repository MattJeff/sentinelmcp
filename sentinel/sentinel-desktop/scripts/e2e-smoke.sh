#!/usr/bin/env bash
# End-to-end smoke test for Sentinel MCP desktop.
# - Launches `pnpm dev` (Vite on :1420)
# - Verifies HTML is served and contains <div id="root">
# - Captures a screenshot of the running dashboard
# - If the bundled .app exists, also launches it and screenshots it
#
# Exits 0 only when the Vite serve + HTML probe succeed.

set -uo pipefail

# Resolve project root (parent of this script's directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

SHOTS_DIR="${PROJECT_ROOT}/docs/screenshots"
DEV_LOG="${PROJECT_ROOT}/.e2e-dev.log"
PORT=1420
URL="http://localhost:${PORT}"

mkdir -p "${SHOTS_DIR}"

DEV_PID=""
APP_BUNDLE=""

cleanup() {
  local code=$?
  if [[ -n "${DEV_PID}" ]] && kill -0 "${DEV_PID}" 2>/dev/null; then
    echo "[smoke] stopping vite dev server (pid=${DEV_PID})"
    kill "${DEV_PID}" 2>/dev/null || true
    # Give it a moment, then force-kill if still alive.
    sleep 1
    if kill -0 "${DEV_PID}" 2>/dev/null; then
      kill -9 "${DEV_PID}" 2>/dev/null || true
    fi
  fi
  # Also try to kill any stray vite on the port (best-effort, do not fail on this).
  if command -v lsof >/dev/null 2>&1; then
    local stray
    stray="$(lsof -ti :${PORT} 2>/dev/null || true)"
    if [[ -n "${stray}" ]]; then
      kill ${stray} 2>/dev/null || true
    fi
  fi
  exit "${code}"
}
trap cleanup EXIT INT TERM

echo "[smoke] project root: ${PROJECT_ROOT}"
echo "[smoke] starting 'pnpm dev' in background..."
# Use nohup-like detach: run in background, redirect logs.
pnpm dev >"${DEV_LOG}" 2>&1 &
DEV_PID=$!
echo "[smoke] vite pid=${DEV_PID}, logs=${DEV_LOG}"

# Wait for the port to be listening (busywait up to 60s).
echo "[smoke] waiting for ${URL} (max 60s)..."
READY=0
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null --max-time 1 "${URL}/" 2>/dev/null; then
    READY=1
    break
  fi
  # Bail early if the dev server already died.
  if ! kill -0 "${DEV_PID}" 2>/dev/null; then
    echo "[smoke] ERROR: vite exited early. Last log lines:" >&2
    tail -n 20 "${DEV_LOG}" >&2 || true
    exit 1
  fi
  sleep 1
done

if [[ "${READY}" -ne 1 ]]; then
  echo "[smoke] ERROR: vite did not become ready on ${URL} within 60s" >&2
  tail -n 30 "${DEV_LOG}" >&2 || true
  exit 1
fi

echo "[smoke] HEAD of served HTML:"
HTML="$(curl -fsS "${URL}/")" || {
  echo "[smoke] ERROR: failed to fetch ${URL}/" >&2
  exit 1
}
printf '%s\n' "${HTML}" | head -5

if ! printf '%s' "${HTML}" | grep -q '<div id="root">'; then
  echo "[smoke] ERROR: served HTML did not contain <div id=\"root\">" >&2
  exit 1
fi
echo "[smoke] OK: HTML contains <div id=\"root\">"

# Open the URL briefly so the screenshot has something on screen.
SHOT_VITE="${SHOTS_DIR}/dashboard-vite-dev.png"
if command -v open >/dev/null 2>&1 && command -v screencapture >/dev/null 2>&1; then
  echo "[smoke] opening ${URL} for screenshot..."
  open "${URL}" >/dev/null 2>&1 || true
  sleep 3
  echo "[smoke] capturing screen -> ${SHOT_VITE}"
  screencapture -x "${SHOT_VITE}" || echo "[smoke] WARN: screencapture failed (non-fatal)"
else
  echo "[smoke] WARN: 'open' or 'screencapture' missing, skipping dev screenshot"
fi

# Optional: also test the bundled .app if it exists.
SHOT_APP="${SHOTS_DIR}/dashboard-app.png"
APP_CANDIDATES=(
  "${PROJECT_ROOT}/src-tauri/target/release/bundle/macos/Sentinel MCP.app"
  "/Applications/Sentinel MCP.app"
)
for cand in "${APP_CANDIDATES[@]}"; do
  if [[ -d "${cand}" ]]; then
    APP_BUNDLE="${cand}"
    break
  fi
done

if [[ -n "${APP_BUNDLE}" ]]; then
  echo "[smoke] found app bundle: ${APP_BUNDLE}"
  open -a "${APP_BUNDLE}" --background >/dev/null 2>&1 || \
    open "${APP_BUNDLE}" >/dev/null 2>&1 || true
  sleep 3
  screencapture -x "${SHOT_APP}" || echo "[smoke] WARN: screencapture for app failed (non-fatal)"
  osascript -e 'tell application "Sentinel MCP" to quit' >/dev/null 2>&1 || true
else
  echo "[smoke] no Sentinel MCP.app bundle found; skipping native app probe"
fi

echo "[smoke] done. screenshots dir: ${SHOTS_DIR}"
ls -la "${SHOTS_DIR}" || true

# Cleanup handled by trap.
exit 0

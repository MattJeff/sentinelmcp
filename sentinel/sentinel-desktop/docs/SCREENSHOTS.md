# Sentinel MCP Desktop — Screenshots

This file documents the screenshots produced by the end-to-end smoke test
(`scripts/e2e-smoke.sh`). All captures are written to
`docs/screenshots/` (relative to the repo root).

## How they are produced

Run from the project root:

```bash
bash scripts/e2e-smoke.sh
```

The script:

1. Starts `pnpm dev` (Vite) on port `1420` in the background.
2. Polls `http://localhost:1420/` until it responds (max 60 s) and asserts
   that the served HTML contains `<div id="root">`.
3. Opens the URL in the default browser, waits ~3 s, and runs
   `screencapture -x` to grab the whole screen.
4. If a built `Sentinel MCP.app` bundle is found
   (`src-tauri/target/release/bundle/macos/Sentinel MCP.app` or
   `/Applications/Sentinel MCP.app`), the script also launches the native
   app, screenshots it, and quits it via AppleScript.
5. Stops the dev server and exits.

## Captures

### `docs/screenshots/dashboard-vite-dev.png`

- **Caption:** Sentinel MCP dashboard rendered by the Vite dev server on
  `http://localhost:1420` during the e2e smoke run. Proves that the React
  app boots end-to-end (HTML shell served, `#root` mounted, app rendered
  in a real browser).
- **Source:** `scripts/e2e-smoke.sh` step 3 (`screencapture -x`).
- **Produced:** every time `bash scripts/e2e-smoke.sh` runs successfully.

### `docs/screenshots/dashboard-app.png` (optional)

- **Caption:** Sentinel MCP dashboard rendered inside the bundled Tauri
  macOS app (`Sentinel MCP.app`). This screenshot is only produced if the
  app bundle has already been built (e.g. by `cargo tauri build --bundles
  app`); otherwise the smoke script skips it and logs
  `no Sentinel MCP.app bundle found; skipping native app probe`.
- **Source:** `scripts/e2e-smoke.sh` step 4 (`screencapture -x` after
  `open -a "Sentinel MCP.app" --background`).
- **Produced:** only when a `.app` bundle is present.

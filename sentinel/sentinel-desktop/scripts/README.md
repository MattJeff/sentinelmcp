# Sentinel MCP - macOS build scripts

## Prerequisites

- **Rust** (stable toolchain) — install via `rustup` (https://rustup.rs).
- **Xcode Command Line Tools** — `xcode-select --install`.
- **Node.js 20+**.
- **pnpm 10+** — `npm install -g pnpm` or `corepack enable`.

The Tauri CLI is provided locally through `@tauri-apps/cli` and is invoked as
`cargo tauri`. No global install is required.

## One command

From the `sentinel-desktop/` project root:

```bash
bash scripts/build-mac.sh
```

The script will:

1. `cd` into the project root.
2. Install JS dependencies with `pnpm install --frozen-lockfile`
   (falls back to plain `pnpm install` if no lockfile is present).
3. Build the frontend (`pnpm build` -> `dist/`).
4. Build the Tauri bundles (`cargo tauri build --bundles app,dmg`).
5. Print the path, human-readable size, and SHA-256 checksum of the DMG.

## Artefact location

On Apple Silicon, the DMG lands at:

```
src-tauri/target/release/bundle/dmg/Sentinel MCP_0.1.0_aarch64.dmg
```

On Intel Macs the suffix becomes `_x64.dmg`. The intermediate `.app`
bundle is also produced under
`src-tauri/target/release/bundle/macos/Sentinel MCP.app`.

## Signing & notarization

The build is **unsigned by default** — fine for local development and
for trusted internal distribution. macOS Gatekeeper will warn on first
launch (right-click -> Open, or `xattr -d com.apple.quarantine` on the
`.app`).

For public distribution you need:

- An Apple Developer ID Application certificate installed in the
  login keychain.
- The `bundle.macOS.signingIdentity` field in
  `src-tauri/tauri.conf.json` set to that identity (e.g.
  `"Developer ID Application: Your Name (TEAMID)"`).
- Optionally, an entitlements `.plist` referenced via
  `bundle.macOS.entitlements`.
- Notarization via `xcrun notarytool submit` once the DMG is built,
  followed by `xcrun stapler staple` to attach the ticket.

None of this is required to produce a working local DMG.

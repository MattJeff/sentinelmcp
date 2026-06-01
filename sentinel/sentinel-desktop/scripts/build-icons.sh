#!/usr/bin/env bash
# Sentinel MCP icon builder.
#
# Produces a 1024x1024 master PNG (shield + MCP lens, blue->purple gradient,
# frosted glass feel) and from it derives the sizes Tauri/macOS need.
#
# Strategy: a small Python program using Pillow renders the artwork. Pillow is
# pure-Python + libjpeg/zlib and is widely available, including on the system
# Python that ships with Homebrew on macOS. If Pillow is missing we try to
# install it into a local venv (no global writes).
#
# After the PNGs are emitted we build an .iconset and run macOS' built-in
# `iconutil` to assemble the .icns.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ICONS_DIR="$ROOT/src-tauri/icons"
ICONSET_DIR="$ICONS_DIR/icon.iconset"

mkdir -p "$ICONS_DIR" "$ICONSET_DIR"

PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c "import PIL" >/dev/null 2>&1; then
  echo "Pillow not found, attempting to install in a local venv..." >&2
  "$PYTHON" -m venv "$HERE/.venv"
  # shellcheck disable=SC1091
  source "$HERE/.venv/bin/activate"
  pip install --quiet --upgrade pip
  pip install --quiet pillow
  PYTHON="$(command -v python)"
fi

"$PYTHON" "$HERE/build_icons.py" --out "$ICONS_DIR"

# Build .iconset (Apple's expected names)
cp "$ICONS_DIR/icon_16x16.png"     "$ICONSET_DIR/icon_16x16.png"
cp "$ICONS_DIR/icon_16x16@2x.png"  "$ICONSET_DIR/icon_16x16@2x.png"
cp "$ICONS_DIR/icon_32x32.png"     "$ICONSET_DIR/icon_32x32.png"
cp "$ICONS_DIR/icon_32x32@2x.png"  "$ICONSET_DIR/icon_32x32@2x.png"
cp "$ICONS_DIR/icon_128x128.png"   "$ICONSET_DIR/icon_128x128.png"
cp "$ICONS_DIR/icon_128x128@2x.png" "$ICONSET_DIR/icon_128x128@2x.png"
cp "$ICONS_DIR/icon_256x256.png"   "$ICONSET_DIR/icon_256x256.png"
cp "$ICONS_DIR/icon_256x256@2x.png" "$ICONSET_DIR/icon_256x256@2x.png"
cp "$ICONS_DIR/icon_512x512.png"   "$ICONSET_DIR/icon_512x512.png"
cp "$ICONS_DIR/icon_512x512@2x.png" "$ICONSET_DIR/icon_512x512@2x.png"

iconutil -c icns "$ICONSET_DIR" -o "$ICONS_DIR/icon.icns"

# Tauri-named copies
cp "$ICONS_DIR/icon_32x32.png"    "$ICONS_DIR/32x32.png"
cp "$ICONS_DIR/icon_128x128.png"  "$ICONS_DIR/128x128.png"
cp "$ICONS_DIR/icon_256x256.png"  "$ICONS_DIR/128x128@2x.png"
cp "$ICONS_DIR/icon_512x512@2x.png" "$ICONS_DIR/icon.png"

echo "Done. Icons in $ICONS_DIR"

#!/usr/bin/env python3
"""
Renders the Sentinel MCP icon set.

Design:
  - SF Symbols-style rounded shield silhouette.
  - Sentinel gradient: blue (#3B82F6) at top -> indigo (#6366F1) -> purple
    (#A855F7) at bottom.
  - Frosted-glass feel: faint inner highlight, soft inner shadow, subtle
    radial vignette inside the shield.
  - Central MCP "eye/lens": concentric rings + small dot, drawn in white
    with reduced alpha to read as etched glass.

The 1024 master is rendered at 4x supersample (4096) and downsampled with
LANCZOS for crisp edges, then all derived sizes are produced from it.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter


# ---------- color helpers ----------

def lerp(a: int, b: int, t: float) -> int:
    return int(round(a + (b - a) * t))


def lerp_color(c1, c2, t):
    return (lerp(c1[0], c2[0], t), lerp(c1[1], c2[1], t), lerp(c1[2], c2[2], t))


def gradient_color(t: float):
    """Sentinel gradient: blue -> indigo -> purple."""
    blue = (59, 130, 246)
    indigo = (99, 102, 241)
    purple = (168, 85, 247)
    if t < 0.5:
        return lerp_color(blue, indigo, t / 0.5)
    return lerp_color(indigo, purple, (t - 0.5) / 0.5)


# ---------- geometry ----------

def shield_path(w: int, h: int):
    """Return a list of (x,y) points tracing a rounded SF-style shield."""
    # Normalised shield in a [0,1] box, then scaled.
    # Shape: flat-ish rounded top, soft shoulders, smooth bottom point.
    pts_norm = [
        (0.50, 0.04),
        (0.78, 0.10),
        (0.92, 0.18),
        (0.94, 0.30),
        (0.92, 0.50),
        (0.86, 0.68),
        (0.74, 0.84),
        (0.58, 0.95),
        (0.50, 0.98),
        (0.42, 0.95),
        (0.26, 0.84),
        (0.14, 0.68),
        (0.08, 0.50),
        (0.06, 0.30),
        (0.08, 0.18),
        (0.22, 0.10),
    ]
    return [(int(x * w), int(y * h)) for x, y in pts_norm]


# ---------- rendering ----------

def render_master(size: int) -> Image.Image:
    """Render the icon at `size` pixels (square). Returns RGBA image."""
    SS = 4  # supersample factor
    W = size * SS
    H = size * SS

    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))

    # ----- shield mask -----
    mask = Image.new("L", (W, H), 0)
    mdraw = ImageDraw.Draw(mask)
    pts = shield_path(W, H)
    mdraw.polygon(pts, fill=255)
    # Soften corners a touch by blur+threshold
    mask = mask.filter(ImageFilter.GaussianBlur(radius=W * 0.004))

    # ----- gradient fill -----
    grad = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gpix = grad.load()
    for y in range(H):
        t = y / (H - 1)
        r, g, b = gradient_color(t)
        for x in range(W):
            gpix[x, y] = (r, g, b, 255)

    # Subtle diagonal sheen (frosted glass highlight)
    sheen = Image.new("L", (W, H), 0)
    sdraw = ImageDraw.Draw(sheen)
    # diagonal band
    band_w = int(W * 0.55)
    for i in range(-H, W, 2):
        # parallel diagonal lines forming a band, alpha modulated
        pass
    # Easier: paint a rotated ellipse highlight near top-left.
    hl = Image.new("L", (W, H), 0)
    hldraw = ImageDraw.Draw(hl)
    hldraw.ellipse(
        [int(W * 0.05), int(H * 0.02), int(W * 0.75), int(H * 0.45)],
        fill=110,
    )
    hl = hl.filter(ImageFilter.GaussianBlur(radius=W * 0.04))

    # Compose gradient + highlight, masked by shield
    shield = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    shield.paste(grad, (0, 0))
    # add white highlight
    white_layer = Image.new("RGBA", (W, H), (255, 255, 255, 0))
    white_layer.putalpha(hl)
    shield = Image.alpha_composite(shield, white_layer)

    # Inner vignette (darker edges for depth)
    vign = Image.new("L", (W, H), 0)
    vdraw = ImageDraw.Draw(vign)
    pad = int(W * 0.04)
    vdraw.ellipse(
        [pad, pad, W - pad, H - pad],
        fill=0,
        outline=None,
    )
    # invert: dark ring near border
    edge = Image.new("L", (W, H), 0)
    edraw = ImageDraw.Draw(edge)
    edraw.polygon(pts, fill=0, outline=255)
    edge = edge.filter(ImageFilter.GaussianBlur(radius=W * 0.025))
    shadow_layer = Image.new("RGBA", (W, H), (12, 10, 40, 0))
    shadow_layer.putalpha(edge)
    shield = Image.alpha_composite(shield, shadow_layer)

    # Apply shield mask
    shield.putalpha(mask)

    # ----- drop shadow behind shield -----
    sh_mask = mask.copy().filter(ImageFilter.GaussianBlur(radius=W * 0.02))
    shadow_bg = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    sb = Image.new("RGBA", (W, H), (10, 8, 30, 180))
    sb.putalpha(sh_mask)
    # offset down a bit
    offset = int(W * 0.012)
    img.paste(sb, (0, offset), sb)

    # Composite shield onto canvas
    img = Image.alpha_composite(img, shield)

    # ----- MCP lens (concentric rings + dot) -----
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    odraw = ImageDraw.Draw(overlay)
    cx, cy = W // 2, int(H * 0.52)

    # outer ring
    r1 = int(W * 0.22)
    stroke1 = int(W * 0.018)
    odraw.ellipse(
        [cx - r1, cy - r1, cx + r1, cy + r1],
        outline=(255, 255, 255, 235),
        width=stroke1,
    )
    # middle ring
    r2 = int(W * 0.14)
    stroke2 = int(W * 0.014)
    odraw.ellipse(
        [cx - r2, cy - r2, cx + r2, cy + r2],
        outline=(255, 255, 255, 200),
        width=stroke2,
    )
    # inner dot / pupil
    r3 = int(W * 0.055)
    odraw.ellipse(
        [cx - r3, cy - r3, cx + r3, cy + r3],
        fill=(255, 255, 255, 255),
    )

    # tiny specular highlight on the dot
    r4 = int(W * 0.018)
    hx, hy = cx - int(r3 * 0.35), cy - int(r3 * 0.35)
    odraw.ellipse(
        [hx - r4, hy - r4, hx + r4, hy + r4],
        fill=(255, 255, 255, 255),
    )

    img = Image.alpha_composite(img, overlay)

    # Downsample to target size
    final = img.resize((size, size), Image.LANCZOS)
    return final


# ---------- driver ----------

SIZES = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
    ("icon.png", 1024),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Render 1024 master once, then downsample for the rest
    print("Rendering 1024x1024 master...")
    master = render_master(1024)
    master.save(out / "icon.png", "PNG", optimize=True)

    for name, size in SIZES:
        if name == "icon.png":
            continue
        print(f"  -> {name} ({size}x{size})")
        if size == 1024:
            master.save(out / name, "PNG", optimize=True)
        else:
            master.resize((size, size), Image.LANCZOS).save(
                out / name, "PNG", optimize=True
            )

    # Also emit a Windows .ico (multi-resolution) from the master
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                 (128, 128), (256, 256)]
    master.save(out / "icon.ico", format="ICO", sizes=ico_sizes)
    print("icon.ico written.")

    print("All PNGs written.")


if __name__ == "__main__":
    main()

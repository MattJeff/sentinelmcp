#!/usr/bin/env bash
# Met a jour la formule Homebrew du tap MattJeff/homebrew-sentinel a partir
# d'une release PUBLIEE de MattJeff/sentinelmcp.
#
# Usage : scripts/release-tap.sh v0.8.0
#
# Telecharge les .sha256 des artefacts CLI de la release, regenere
# Formula/sentinel.rb (version + 4 sha256 unix) et pousse dans le tap.
# Requiert : gh authentifie avec acces en ecriture au tap.
set -euo pipefail

TAG="${1:?usage: release-tap.sh <tag>  (ex: v0.8.0)}"
VERSION="${TAG#v}"
REPO="MattJeff/sentinelmcp"
TAP="MattJeff/homebrew-sentinel"

TARGETS="aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "==> Telechargement des checksums de $TAG"
gh release download "$TAG" --repo "$REPO" --dir "$tmp" --pattern '*.tar.gz.sha256' --clobber

sha() { # cible -> sha256
  local f="$tmp/sentinel-${VERSION}-$1.tar.gz.sha256"
  [ -f "$f" ] || { echo "manquant: $f (la release publie-t-elle des binaires ?)" >&2; exit 1; }
  awk '{print $1}' "$f"
}
SHA_MAC_ARM="$(sha aarch64-apple-darwin)"
SHA_MAC_X86="$(sha x86_64-apple-darwin)"
SHA_LIN_ARM="$(sha aarch64-unknown-linux-gnu)"
SHA_LIN_X86="$(sha x86_64-unknown-linux-gnu)"

echo "==> Regeneration de la formule (v$VERSION)"
# En CI, HOMEBREW_TAP_TOKEN (PAT avec droit d'ecriture sur le tap) authentifie
# le clone/push. En local, on s'appuie sur l'auth git/gh existante.
if [ -n "${HOMEBREW_TAP_TOKEN:-}" ]; then
  TAP_URL="https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${TAP}.git"
else
  TAP_URL="https://github.com/${TAP}.git"
fi
git clone -q "$TAP_URL" "$tmp/tap"
mkdir -p "$tmp/tap/Formula"
cat > "$tmp/tap/Formula/sentinel.rb" <<EOF
# Genere par scripts/release-tap.sh — ne pas editer a la main.
class Sentinel < Formula
  desc "Local-first EDR for MCP servers — discover, fingerprint and monitor MCP servers"
  homepage "https://sentinelmcp.dev"
  version "${VERSION}"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/${REPO}/releases/download/v#{version}/sentinel-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "${SHA_MAC_ARM}"
    end
    on_intel do
      url "https://github.com/${REPO}/releases/download/v#{version}/sentinel-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "${SHA_MAC_X86}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/${REPO}/releases/download/v#{version}/sentinel-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "${SHA_LIN_ARM}"
    end
    on_intel do
      url "https://github.com/${REPO}/releases/download/v#{version}/sentinel-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "${SHA_LIN_X86}"
    end
  end

  def install
    bin.install "sentinel"
  end

  test do
    assert_match "sentinel", shell_output("#{bin}/sentinel --version")
  end
end
EOF

cd "$tmp/tap"
git add Formula/sentinel.rb
if git diff --cached --quiet; then echo "==> Formule deja a jour"; exit 0; fi
git -c user.email="noreply@anthropic.com" -c user.name="Sentinel Release" \
  commit -q -m "sentinel ${VERSION}"
git push -q origin HEAD
echo "==> Tap mis a jour : brew install ${TAP%/*}/sentinel/sentinel"

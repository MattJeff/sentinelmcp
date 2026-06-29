#!/bin/sh
# Sentinel MCP — installeur CLI (Unix : macOS / Linux).
# Usage : curl -fsSL https://sentinelmcp.dev/install.sh | sh
#
# Telecharge le binaire `sentinel` depuis la derniere GitHub Release, verifie
# son SHA-256, et l'installe dans un repertoire du PATH. 100% transparent :
# aucune telemetrie, aucune execution distante autre que le telechargement de
# l'artefact signe de la release.
set -eu

REPO="MattJeff/sentinelmcp"
BINAIRE="sentinel"

err() { printf '\033[31merreur:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$1"; }

# --- Detection de la cible -------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin) triple_os="apple-darwin" ;;
  Linux)  triple_os="unknown-linux-gnu" ;;
  *) err "OS non supporte par cet installeur : $os (Windows : voir les Releases). Sinon, build source : https://github.com/$REPO#install" ;;
esac
case "$arch" in
  x86_64|amd64) triple_arch="x86_64" ;;
  arm64|aarch64) triple_arch="aarch64" ;;
  *) err "architecture non supportee : $arch" ;;
esac
target="${triple_arch}-${triple_os}"

# --- Outils requis ---------------------------------------------------------
command -v curl >/dev/null 2>&1 || err "curl est requis"
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum";
elif command -v shasum >/dev/null 2>&1; then SHA="shasum -a 256";
else err "sha256sum/shasum requis pour verifier le checksum"; fi

# --- Derniere version ------------------------------------------------------
info "Recherche de la derniere release de $REPO"
tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
[ -n "${tag:-}" ] || err "impossible de determiner la derniere release"
version="${tag#v}"

artefact="${BINAIRE}-${version}-${target}.tar.gz"
base="https://github.com/$REPO/releases/download/${tag}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "Telechargement de $artefact"
curl -fsSL -o "$tmp/$artefact" "$base/$artefact" 2>/dev/null || err \
  "artefact $artefact introuvable dans la release $tag. Cette release ne publie peut-etre pas (encore) de binaires multi-OS. Build source : https://github.com/$REPO#install"

# --- Verification du checksum ---------------------------------------------
if curl -fsSL -o "$tmp/$artefact.sha256" "$base/$artefact.sha256" 2>/dev/null; then
  attendu="$(awk '{print $1}' "$tmp/$artefact.sha256")"
  obtenu="$($SHA "$tmp/$artefact" | awk '{print $1}')"
  [ "$attendu" = "$obtenu" ] || err "checksum SHA-256 invalide (attendu $attendu, obtenu $obtenu)"
  info "Checksum SHA-256 verifie"
else
  printf '\033[33mattention:\033[0m %s.sha256 absent — checksum non verifie\n' "$artefact" >&2
fi

tar -xzf "$tmp/$artefact" -C "$tmp"
[ -f "$tmp/$BINAIRE" ] || err "binaire $BINAIRE introuvable dans l'archive"
chmod +x "$tmp/$BINAIRE"

# --- Choix du repertoire d'installation ------------------------------------
if [ -w "/usr/local/bin" ] 2>/dev/null; then dest="/usr/local/bin";
elif [ "$(id -u)" = "0" ]; then dest="/usr/local/bin";
else dest="$HOME/.local/bin"; mkdir -p "$dest"; fi

mv "$tmp/$BINAIRE" "$dest/$BINAIRE"
info "Installe : $dest/$BINAIRE ($tag)"

case ":$PATH:" in
  *":$dest:"*) : ;;
  *) printf '\033[33mAjoute %s a ton PATH :\033[0m  export PATH="%s:$PATH"\n' "$dest" "$dest" ;;
esac

printf '\n\033[32mPret.\033[0m  Lance :  %s scan\n' "$BINAIRE"

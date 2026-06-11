#!/usr/bin/env bash
#
# Installeur Sentinel MCP (CLI) pour macOS et Linux.
#
# Usage :
#   curl -fsSL https://raw.githubusercontent.com/MattJeff/sentinelmcp/main/scripts/install.sh | bash
#
# Variables d'environnement optionnelles :
#   SENTINEL_VERSION      version a installer sans le "v" (defaut : derniere release)
#   SENTINEL_INSTALL_DIR  dossier d'installation (defaut : ~/.local/bin, sinon /usr/local/bin)
#
set -euo pipefail

REPO="MattJeff/sentinelmcp"
BINARY="sentinel"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mattention :\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merreur :\033[0m %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl est requis"
command -v tar >/dev/null 2>&1 || die "tar est requis"

# --- Detection OS / architecture --------------------------------------------
os="$(uname -s)"
case "$os" in
  Darwin) triple_os="apple-darwin" ;;
  Linux)  triple_os="unknown-linux-gnu" ;;
  *)      die "systeme non supporte : $os (utilisez scripts/install.ps1 sous Windows)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  triple_arch="x86_64" ;;
  arm64|aarch64) triple_arch="aarch64" ;;
  *)             die "architecture non supportee : $arch" ;;
esac

target="${triple_arch}-${triple_os}"
info "Cible detectee : ${target}"

# --- Resolution de la version -----------------------------------------------
version="${SENTINEL_VERSION:-}"
if [ -z "$version" ]; then
  info "Recherche de la derniere release..."
  api_json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")" \
    || die "appel a l'API GitHub impossible (reseau coupe ou rate-limit) — reessayez ou definissez SENTINEL_VERSION"
  tag="$(printf '%s\n' "$api_json" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
    || true)"
  [ -n "$tag" ] || die "impossible de determiner la derniere release de ${REPO}"
  version="${tag#v}"
fi
info "Version : ${version}"

artifact="sentinel-${version}-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/v${version}"

# --- Telechargement -----------------------------------------------------------
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

info "Telechargement de ${artifact}..."
curl -fsSL -o "${tmpdir}/${artifact}" "${base_url}/${artifact}" \
  || die "telechargement impossible : ${base_url}/${artifact}"

# --- Verification du checksum -------------------------------------------------
if curl -fsSL -o "${tmpdir}/${artifact}.sha256" "${base_url}/${artifact}.sha256" 2>/dev/null; then
  info "Verification du checksum SHA-256..."
  expected="$(awk '{print $1}' "${tmpdir}/${artifact}.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${tmpdir}/${artifact}" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "${tmpdir}/${artifact}" | awk '{print $1}')"
  fi
  [ "$expected" = "$actual" ] \
    || die "checksum invalide (attendu ${expected}, obtenu ${actual}) — archive corrompue ou compromise"
  info "Checksum OK"
else
  warn "fichier ${artifact}.sha256 introuvable sur la release — checksum non verifie"
fi

# --- Extraction et installation ------------------------------------------------
tar -xzf "${tmpdir}/${artifact}" -C "$tmpdir"
[ -f "${tmpdir}/${BINARY}" ] || die "binaire ${BINARY} introuvable dans l'archive"

install_dir="${SENTINEL_INSTALL_DIR:-}"
if [ -z "$install_dir" ]; then
  if [ -d "${HOME}/.local/bin" ] || mkdir -p "${HOME}/.local/bin" 2>/dev/null; then
    install_dir="${HOME}/.local/bin"
  elif [ -w /usr/local/bin ]; then
    install_dir="/usr/local/bin"
  else
    die "aucun dossier d'installation accessible (definissez SENTINEL_INSTALL_DIR)"
  fi
fi
mkdir -p "$install_dir"

install -m 755 "${tmpdir}/${BINARY}" "${install_dir}/${BINARY}"
info "Installe : ${install_dir}/${BINARY}"

case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *) warn "${install_dir} n'est pas dans votre PATH — ajoutez : export PATH=\"${install_dir}:\$PATH\"" ;;
esac

info "Termine. Lancez : ${BINARY} --help"

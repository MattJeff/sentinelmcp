#!/usr/bin/env bash
#
# Test fonctionnel de scripts/install.sh, sans reseau : un shim `curl` place
# en tete de PATH sert des fixtures locales a la place des releases GitHub.
#
# Usage : bash scripts/test_install.sh
#
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

ok()   { printf '\033[1;32mOK\033[0m  %s\n' "$*"; }
fail() { printf '\033[1;31mECHEC\033[0m %s\n' "$*" >&2; exit 1; }

# --- Cible locale (la meme que celle que detectera install.sh) -----------------
os="$(uname -s)"
case "$os" in
  Darwin) triple_os="apple-darwin" ;;
  Linux)  triple_os="unknown-linux-gnu" ;;
  *)      echo "test ignore : OS non supporte ($os)"; exit 0 ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  triple_arch="x86_64" ;;
  arm64|aarch64) triple_arch="aarch64" ;;
  *)             echo "test ignore : architecture non supportee ($arch)"; exit 0 ;;
esac
version="9.9.9"
artifact="sentinel-${version}-${triple_arch}-${triple_os}.tar.gz"

# --- Fixtures : archive de release + checksum -----------------------------------
mkdir -p "$workdir/fixtures" "$workdir/bin" "$workdir/payload"
printf '#!/bin/sh\necho "sentinel factice"\n' > "$workdir/payload/sentinel"
chmod +x "$workdir/payload/sentinel"

make_fixtures() {
  tar -czf "$workdir/fixtures/$artifact" -C "$workdir/payload" sentinel
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$workdir/fixtures" && sha256sum "$artifact" > "$artifact.sha256")
  else
    (cd "$workdir/fixtures" && shasum -a 256 "$artifact" > "$artifact.sha256")
  fi
}
make_fixtures

# --- Shim curl : sert les fixtures au lieu du reseau -----------------------------
cat > "$workdir/bin/curl" <<SHIM
#!/usr/bin/env bash
# Shim de test : intercepte "curl [-fsSL] [-o OUT] URL" et sert
# $workdir/fixtures/<basename de l'URL>.
out=""
url=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    -*) shift ;;
    *)  url="\$1"; shift ;;
  esac
done
file="$workdir/fixtures/\$(basename "\$url")"
[ -f "\$file" ] || exit 22
if [ -n "\$out" ]; then cp "\$file" "\$out"; else cat "\$file"; fi
SHIM
chmod +x "$workdir/bin/curl"

# $1 : dossier d'installation ; $2 (optionnel) : SENTINEL_VERSION
# ("" = non definie => resolution via l'API GitHub, servie par le shim).
run_install() {
  PATH="$workdir/bin:$PATH" \
    SENTINEL_VERSION="${2-$version}" \
    SENTINEL_INSTALL_DIR="$1" \
    bash "$script_dir/install.sh"
}

# --- Cas 1 : installation nominale (checksum valide) ------------------------------
run_install "$workdir/install" >/dev/null
[ -x "$workdir/install/sentinel" ] || fail "binaire non installe dans $workdir/install"
[ "$("$workdir/install/sentinel")" = "sentinel factice" ] || fail "binaire installe inattendu"
ok "installation nominale, checksum verifie"

# --- Cas 2 : checksum corrompu => echec obligatoire --------------------------------
printf '%064d  %s\n' 0 "$artifact" > "$workdir/fixtures/$artifact.sha256"
if run_install "$workdir/install2" >/dev/null 2>&1; then
  fail "un checksum invalide aurait du faire echouer l'installation"
fi
[ ! -e "$workdir/install2/sentinel" ] || fail "binaire installe malgre un checksum invalide"
ok "checksum invalide rejete, rien n'est installe"

# --- Cas 3 : artefact absent => message d'erreur clair ------------------------------
rm "$workdir/fixtures/$artifact"
if out="$(run_install "$workdir/install3" 2>&1)"; then
  fail "une release introuvable aurait du faire echouer l'installation"
fi
printf '%s\n' "$out" | grep -q "telechargement impossible" \
  || fail "message d'erreur inattendu : $out"
ok "release introuvable signalee proprement"

# --- Cas 4 : resolution de la derniere version via l'API GitHub --------------------
# Sans SENTINEL_VERSION, install.sh appelle .../releases/latest : le shim sert
# la fixture "latest" (basename de l'URL de l'API).
make_fixtures
printf '{\n  "tag_name": "v%s",\n  "name": "Sentinel MCP v%s"\n}\n' "$version" "$version" \
  > "$workdir/fixtures/latest"
run_install "$workdir/install4" "" >/dev/null
[ -x "$workdir/install4/sentinel" ] || fail "binaire non installe via la resolution API"
[ "$("$workdir/install4/sentinel")" = "sentinel factice" ] || fail "binaire installe inattendu (cas API)"
ok "derniere version resolue via l'API GitHub (tag_name)"

echo "Tous les tests passent"

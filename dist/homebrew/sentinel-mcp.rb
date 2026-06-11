# typed: strict
# frozen_string_literal: true

# Formule Homebrew pour la CLI Sentinel MCP.
#
# IMPORTANT — emplacement : Homebrew ne scanne que Formula/, HomebrewFormula/
# ou la racine d'un depot tape. Ce fichier (dist/homebrew/) n'est donc PAS
# installable via `brew tap MattJeff/sentinelmcp <url>` tel quel. Deux usages :
#   - installation directe depuis un fichier local :
#       curl -fsSLO https://raw.githubusercontent.com/MattJeff/sentinelmcp/main/dist/homebrew/sentinel-mcp.rb
#       brew install --formula ./sentinel-mcp.rb
#   - tap dedie : copier ce fichier dans Formula/sentinel-mcp.rb d'un depot
#     MattJeff/homebrew-sentinelmcp, puis `brew tap MattJeff/sentinelmcp`
#     et `brew install sentinel-mcp`.
#
# Publication d'une release :
#   1. Mettre a jour `version` ci-dessous.
#   2. Remplacer chaque placeholder REPLACE_WITH_SHA256_<TARGET> par le
#      contenu du fichier sentinel-<version>-<target>.tar.gz.sha256 publie
#      sur https://github.com/MattJeff/sentinelmcp/releases (premiere colonne,
#      64 caracteres hexadecimaux).
#   3. `brew audit --strict sentinel-mcp` puis pousser dans le tap.
#
# Nommage des artefacts attendu : sentinel-<version>-<target>.tar.gz
# contenant le binaire `sentinel` a la racine de l'archive.
class SentinelMcp < Formula
  desc "Securite des serveurs MCP : discovery, probing actif, detection rug-pull"
  homepage "https://github.com/MattJeff/sentinelmcp"
  version "0.1.0"
  license "MIT"

  head do
    url "https://github.com/MattJeff/sentinelmcp.git", branch: "main"

    depends_on "rust" => :build
  end

  on_macos do
    on_arm do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AARCH64_APPLE_DARWIN"
    end
    on_intel do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_X86_64_APPLE_DARWIN"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AARCH64_UNKNOWN_LINUX_GNU"
    end
    on_intel do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_X86_64_UNKNOWN_LINUX_GNU"
    end
  end

  def install
    if build.head?
      # Le workspace Rust vit dans le sous-dossier sentinel/ du depot.
      # std_cargo_args passe --locked : si le clone ne contient pas encore
      # sentinel/Cargo.lock, on le genere pour que le build HEAD reste possible.
      unless (buildpath/"sentinel/Cargo.lock").exist?
        system "cargo", "generate-lockfile", "--manifest-path", "sentinel/Cargo.toml"
      end
      system "cargo", "install", *std_cargo_args(path: "sentinel/crates/sentinel-cli")
    else
      bin.install "sentinel"
    end
  end

  test do
    assert_match "sentinel", shell_output("#{bin}/sentinel --help")
  end
end

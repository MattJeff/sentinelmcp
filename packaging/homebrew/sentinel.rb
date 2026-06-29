# Homebrew formula — Sentinel MCP CLI
#
# Destination : repo tap dédié `MattJeff/homebrew-sentinel` (fichier `Formula/sentinel.rb`).
# Installation utilisateur : `brew install MattJeff/sentinel/sentinel`
#
# Ce fichier est un GABARIT. Remplace la version et les SHA256 par les
# valeurs réelles de la release (`sentinel-<version>-<target>.tar.gz.sha256`).
# `cargo-dist` (voir packaging/cargo-dist.md) génère et met à jour cette formule
# automatiquement à chaque release — préfère ce flux à l'édition manuelle.

class Sentinel < Formula
  desc "Local-first EDR for MCP servers — discover, fingerprint and monitor MCP servers"
  homepage "https://github.com/MattJeff/sentinelmcp"
  version "0.8.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_aarch64-apple-darwin"
    end
    on_intel do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_x86_64-apple-darwin"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_aarch64-unknown-linux-gnu"
    end
    on_intel do
      url "https://github.com/MattJeff/sentinelmcp/releases/download/v#{version}/sentinel-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_x86_64-unknown-linux-gnu"
    end
  end

  def install
    bin.install "sentinel"
  end

  test do
    assert_match "sentinel", shell_output("#{bin}/sentinel --version")
  end
end

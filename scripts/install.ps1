<#
.SYNOPSIS
    Installeur Sentinel MCP (CLI) pour Windows.

.DESCRIPTION
    Telecharge la derniere release GitHub, verifie le checksum SHA-256,
    extrait le binaire et l'installe dans $env:LOCALAPPDATA\Programs\sentinel.

.EXAMPLE
    irm https://raw.githubusercontent.com/MattJeff/sentinelmcp/main/scripts/install.ps1 | iex

.NOTES
    Variables d'environnement optionnelles :
      SENTINEL_VERSION      version a installer sans le "v" (defaut : derniere release)
      SENTINEL_INSTALL_DIR  dossier d'installation
#>
$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 (defaut sur Windows 10) n'active pas toujours TLS 1.2,
# requis par api.github.com.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$Repo = "MattJeff/sentinelmcp"
$Binary = "sentinel.exe"

function Write-Info($Message) { Write-Host "==> $Message" -ForegroundColor Blue }
function Write-Warning2($Message) { Write-Host "attention : $Message" -ForegroundColor Yellow }
# `throw` (et non `exit 1`) : execute via `irm | iex`, `exit` fermerait la
# session PowerShell de l'utilisateur.
function Fail($Message) { throw "erreur : $Message" }

# --- Detection de l'architecture ---------------------------------------------
$arch = $env:PROCESSOR_ARCHITECTURE
switch ($arch) {
    "AMD64" { $target = "x86_64-pc-windows-msvc" }
    "ARM64" {
        # Aucun build aarch64-pc-windows-msvc n'est publie par release.yml :
        # Windows 11 ARM execute les binaires x64 via emulation.
        $target = "x86_64-pc-windows-msvc"
        Write-Info "Windows ARM64 detecte : installation du binaire x86_64 (emulation x64)"
    }
    default { Fail "architecture non supportee : $arch" }
}
Write-Info "Cible detectee : $target"

# --- Resolution de la version --------------------------------------------------
$version = $env:SENTINEL_VERSION
if (-not $version) {
    Write-Info "Recherche de la derniere release..."
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    } catch {
        Fail "impossible de determiner la derniere release de $Repo : $_"
    }
    $version = $release.tag_name -replace "^v", ""
}
Write-Info "Version : $version"

$artifact = "sentinel-$version-$target.tar.gz"
$baseUrl = "https://github.com/$Repo/releases/download/v$version"

# --- Telechargement -------------------------------------------------------------
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-install-$([System.Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
    $archivePath = Join-Path $tmpDir $artifact
    Write-Info "Telechargement de $artifact..."
    try {
        Invoke-WebRequest -Uri "$baseUrl/$artifact" -OutFile $archivePath -UseBasicParsing
    } catch {
        Fail "telechargement impossible : $baseUrl/$artifact"
    }

    # --- Verification du checksum -----------------------------------------------
    $checksumPath = Join-Path $tmpDir "$artifact.sha256"
    $checksumOk = $true
    try {
        Invoke-WebRequest -Uri "$baseUrl/$artifact.sha256" -OutFile $checksumPath -UseBasicParsing
    } catch {
        $checksumOk = $false
        Write-Warning2 "fichier $artifact.sha256 introuvable sur la release — checksum non verifie"
    }
    if ($checksumOk) {
        Write-Info "Verification du checksum SHA-256..."
        $expected = ((Get-Content $checksumPath -Raw).Trim() -split "\s+")[0].ToLower()
        $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLower()
        if ($expected -ne $actual) {
            Fail "checksum invalide (attendu $expected, obtenu $actual) — archive corrompue ou compromise"
        }
        Write-Info "Checksum OK"
    }

    # --- Extraction et installation ----------------------------------------------
    tar -xzf $archivePath -C $tmpDir
    if ($LASTEXITCODE -ne 0) { Fail "extraction de l'archive impossible (tar requis, inclus dans Windows 10+)" }
    $binaryPath = Join-Path $tmpDir $Binary
    if (-not (Test-Path $binaryPath)) { Fail "binaire $Binary introuvable dans l'archive" }

    $installDir = $env:SENTINEL_INSTALL_DIR
    if (-not $installDir) {
        $installDir = Join-Path $env:LOCALAPPDATA "Programs\sentinel"
    }
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item -Path $binaryPath -Destination (Join-Path $installDir $Binary) -Force
    Write-Info "Installe : $(Join-Path $installDir $Binary)"

    # --- PATH utilisateur -----------------------------------------------------------
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ";") -notcontains $installDir) {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
        Write-Info "Dossier ajoute au PATH utilisateur (ouvrez un nouveau terminal)"
    }

    Write-Info "Termine. Lancez : sentinel --help"
} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}

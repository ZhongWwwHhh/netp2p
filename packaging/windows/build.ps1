param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
$ldflags = "-s -w -X github.com/netp2p/netp2p/internal/version.Version=$Version"

try {
  go build -trimpath -ldflags $ldflags -o (Join-Path $BinDir "netp2pd.exe") ./cmd/netp2pd
  go build -trimpath -ldflags $ldflags -o (Join-Path $BinDir "netp2p.exe") ./cmd/netp2p
} finally {
  $env:GOOS = $previousGOOS
  $env:GOARCH = $previousGOARCH
  $env:CGO_ENABLED = $previousCGO
}

Copy-Item packaging/runtime.example.yaml (Join-Path $BinDir "runtime.yaml") -Force
Copy-Item packaging/windows/tray.ps1 (Join-Path $BinDir "tray.ps1") -Force
& (Join-Path $PSScriptRoot "build-msi.ps1") -Version $Version -BinDir $BinDir -OutDir $OutDir

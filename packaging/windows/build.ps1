param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = "Stop"

if ($Version.TrimStart("v") -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
  throw "invalid version '$Version'; expected semantic version"
}
$semanticVersion = $Version.TrimStart("v").Split("+")[0]
$baseVersion = [version]($semanticVersion.Split("-")[0])
$prerelease = if ($semanticVersion.Contains("-")) { $semanticVersion.Split("-")[1] } else { "" }
$prereleaseRevision = if ($prerelease) { [int]([regex]::Match($prerelease, "\d+").Value) } else { 0 }
$fileVersion = [version]::new($baseVersion.Major, $baseVersion.Minor, $baseVersion.Build, $prereleaseRevision)

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
$ldflags = "-s -w -X github.com/netp2p/netp2p/internal/version.Version=$Version"
# go-winres tool version, independent of the NetP2P product version.
$winresVersion = "v0.3.6"
$goBin = go env GOBIN
if (-not $goBin) {
  $goBin = Join-Path (go env GOPATH) "bin"
}
$winresExe = Join-Path $goBin "go-winres.exe"
if (-not (Test-Path $winresExe)) {
  go install "github.com/tc-hib/go-winres@$winresVersion"
}
$resourceDir = Join-Path ([IO.Path]::GetTempPath()) "netp2p-winres-$fileVersion"

try {
  New-Item -ItemType Directory -Force -Path $resourceDir | Out-Null
  $winres = Get-Content (Join-Path $PSScriptRoot "winres.json") -Raw
  $winres = $winres.Replace("0.0.0.0", "$fileVersion")
  $winres = $winres.Replace("@SEMVER@", $semanticVersion)
  [IO.File]::WriteAllText((Join-Path $resourceDir "winres.json"), $winres, [Text.UTF8Encoding]::new($false))
  & $winresExe make --in (Join-Path $resourceDir "winres.json") --out (Join-Path $resourceDir "rsrc") --arch amd64
  $resource = Join-Path $resourceDir "rsrc_windows_amd64.syso"
  if (-not (Test-Path $resource)) {
    throw "go-winres did not create $resource"
  }
  Copy-Item $resource (Join-Path (Get-Location) "cmd\netp2pd\rsrc_windows_amd64.syso") -Force
  Copy-Item $resource (Join-Path (Get-Location) "cmd\netp2p\rsrc_windows_amd64.syso") -Force

  go build -trimpath -ldflags $ldflags -o (Join-Path $BinDir "netp2pd.exe") ./cmd/netp2pd
  go build -trimpath -ldflags $ldflags -o (Join-Path $BinDir "netp2p.exe") ./cmd/netp2p
  go build -trimpath -o (Join-Path $BinDir "netp2p-configcheck.exe") ./packaging/windows/configcheck/cmd
} finally {
  $env:GOOS = $previousGOOS
  $env:GOARCH = $previousGOARCH
  $env:CGO_ENABLED = $previousCGO
  Remove-Item (Join-Path (Get-Location) "cmd\netp2pd\rsrc_windows_amd64.syso") -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path (Get-Location) "cmd\netp2p\rsrc_windows_amd64.syso") -Force -ErrorAction SilentlyContinue
}

Copy-Item packaging/windows/runtime.windows.yaml (Join-Path $BinDir "runtime.yaml") -Force
Copy-Item packaging/windows/tray.ps1 (Join-Path $BinDir "tray.ps1") -Force
& (Join-Path $PSScriptRoot "build-msi.ps1") -Version $Version -BinDir $BinDir -OutDir $OutDir

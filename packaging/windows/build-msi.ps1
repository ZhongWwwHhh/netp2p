param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = "Stop"

$msiVersion = $Version.TrimStart("v").Split("+")[0].Split("-")[0]
try {
  $parsedVersion = [version]::Parse("$msiVersion.0")
} catch {
  throw "invalid MSI product version '$Version'"
}
if ($parsedVersion.Major -gt 255 -or $parsedVersion.Minor -gt 255 -or $parsedVersion.Build -gt 65535) {
  throw "MSI product version '$msiVersion' is outside the Windows Installer range"
}

$wintun = Join-Path $BinDir "wintun.dll"
$wintunVersion = "0.14.1"
$wintunSHA256 = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"
$wintunSignerThumbprint = "DF98E075A012ED8C86FBCF14854B8F9555CB3D45"
if (-not (Test-Path $wintun)) {
  $archive = Join-Path ([IO.Path]::GetTempPath()) "wintun-$wintunVersion.zip"
  Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-$wintunVersion.zip" -OutFile $archive
  $extractDir = Join-Path ([IO.Path]::GetTempPath()) "wintun-$wintunVersion"
  Expand-Archive -LiteralPath $archive -DestinationPath $extractDir -Force
  $extracted = Join-Path $extractDir "wintun\bin\amd64\wintun.dll"
  # The upstream archive is regenerated, so pin the signed DLL instead of the
  # non-deterministic ZIP container.
  $dllHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $extracted).Hash
  if ($dllHash -ne $wintunSHA256) {
    throw "wintun DLL checksum mismatch: expected $wintunSHA256, got $dllHash"
  }
  $signature = Get-AuthenticodeSignature -LiteralPath $extracted
  if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Thumbprint -ne $wintunSignerThumbprint) {
    throw "wintun DLL signature is not valid for WireGuard LLC"
  }
  Copy-Item $extracted $wintun
}

$definitionPath = Join-Path $PSScriptRoot "netp2p.wxs"
if (-not (Test-Path $definitionPath)) {
  throw "missing WiX definition: $definitionPath"
}
$definition = Get-Content $definitionPath -Raw
$referencedFiles = [regex]::Matches($definition, '\$\(var\.BinDir\)\\([^"]+)') |
  ForEach-Object { $_.Groups[1].Value -replace '/', '\' } | Select-Object -Unique
foreach ($referencedFile in $referencedFiles) {
  $candidate = Join-Path $BinDir $referencedFile
  if (-not (Test-Path $candidate)) {
    throw "WiX definition references missing packaging input: $candidate"
  }
}

wix build `
  -arch x64 `
  -define ProductVersion=$msiVersion `
  -define BinDir=$BinDir `
  -out (Join-Path $OutDir "netp2p-$Version-windows-amd64.msi") `
  (Join-Path $PSScriptRoot "netp2p.wxs")

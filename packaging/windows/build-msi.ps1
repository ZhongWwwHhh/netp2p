param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = "Stop"

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

wix build `
  -arch x64 `
  -define ProductVersion=$Version `
  -define BinDir=$BinDir `
  -out (Join-Path $OutDir "netp2p-$Version-windows-amd64.msi") `
  (Join-Path $PSScriptRoot "netp2p.wxs")

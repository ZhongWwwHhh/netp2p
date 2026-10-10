param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = "Stop"

$wintun = Join-Path $BinDir "wintun.dll"
$wintunVersion = "0.14.1"
$wintunSHA256 = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"
if (-not (Test-Path $wintun)) {
  $archive = Join-Path ([IO.Path]::GetTempPath()) "wintun-$wintunVersion.zip"
  Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-$wintunVersion.zip" -OutFile $archive
  $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash
  if ($actualHash -ne $wintunSHA256) {
    throw "wintun archive checksum mismatch: expected $wintunSHA256, got $actualHash"
  }
  $extractDir = Join-Path ([IO.Path]::GetTempPath()) "wintun-$wintunVersion"
  Expand-Archive -LiteralPath $archive -DestinationPath $extractDir -Force
  Copy-Item (Join-Path $extractDir "wintun\bin\amd64\wintun.dll") $wintun
}

wix build `
  -arch x64 `
  -define ProductVersion=$Version `
  -define BinDir=$BinDir `
  -out (Join-Path $OutDir "netp2p-$Version-windows-amd64.msi") `
  (Join-Path $PSScriptRoot "netp2p.wxs")

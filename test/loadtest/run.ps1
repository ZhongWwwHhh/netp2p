param(
    [ValidateSet("quick", "production", "architecture")]
    [string]$Scenario = "quick",
    [string]$Output = "",
    [switch]$KeepRegistry
)

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repoRoot
try {
    $arguments = @("run", "./test/loadtest/cmd", "--scenario", $Scenario)
    if ($Output -ne "") {
        $arguments += @("--output", $Output)
    }
    if ($KeepRegistry) {
        $arguments += "--keep-registry"
    }
    go @arguments
    exit $LASTEXITCODE
} finally {
    Pop-Location
}

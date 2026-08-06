<#
.SYNOPSIS
    Convenience wrapper: imports the MicroBurstSecretsHunter module and runs a scan.

.EXAMPLE
    .\Scan-MicroBurst.ps1 -Path .\MicroBurst-2026

.EXAMPLE
    .\Scan-MicroBurst.ps1 -Path .\dump -OutputDirectory .\report -Verbose
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [string]$OutputDirectory,
    [switch]$IncludeEntropy,
    [double]$MinEntropy = 4.0,
    [switch]$ScanValues,
    [switch]$ShowSecrets,
    [switch]$NoHtml,
    [switch]$NoCsv,
    [switch]$Quiet
)

Import-Module (Join-Path $PSScriptRoot 'MicroBurstSecretsHunter.psd1') -Force

$params = @{
    Path           = $Path
    IncludeEntropy = $IncludeEntropy
    MinEntropy     = $MinEntropy
    ScanValues     = $ScanValues
    ShowSecrets    = $ShowSecrets
    NoHtml         = $NoHtml
    NoCsv          = $NoCsv
    Quiet          = $Quiet
}
if ($OutputDirectory) { $params['OutputDirectory'] = $OutputDirectory }

Invoke-MBSecretScan @params | Out-Null

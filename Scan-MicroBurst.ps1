<#
.SYNOPSIS
    Convenience wrapper: imports the MicroBurstSecretsHunter module and runs a scan.

.DESCRIPTION
    Passes every scan option through to Invoke-MBSecretScan. Adds two options
    for scripted / CI use:

      -FailOnSeverity  exit with code 1 when any finding is at or above this
                       severity (exit 0 otherwise).
      -PassThru        emit the finding objects to the pipeline (by default the
                       wrapper only prints the console summary).

.EXAMPLE
    .\Scan-MicroBurst.ps1 -Path .\MicroBurst-2026

.EXAMPLE
    .\Scan-MicroBurst.ps1 -Path .\dump -OutputDirectory .\report -Verbose

.EXAMPLE
    .\Scan-MicroBurst.ps1 -Path .\dump -Quiet -Sarif -FailOnSeverity High
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [string]$OutputDirectory,
    [switch]$IncludeEntropy,
    [double]$MinEntropy = 4.0,
    [int]$MaxFileSizeMB = 50,
    [string[]]$IncludeExtension,
    [switch]$ScanValues,
    [switch]$ShowSecrets,
    [string]$SuppressionFile,
    [switch]$Sarif,
    [switch]$NoJson,
    [switch]$NoHtml,
    [switch]$NoCsv,
    [switch]$Quiet,

    [ValidateSet('Critical','High','Medium','Low','Info')]
    [string]$FailOnSeverity,

    [switch]$PassThru
)

Import-Module (Join-Path $PSScriptRoot 'MicroBurstSecretsHunter.psd1') -Force

$params = @{
    Path           = $Path
    IncludeEntropy = $IncludeEntropy
    MinEntropy     = $MinEntropy
    MaxFileSizeMB  = $MaxFileSizeMB
    ScanValues     = $ScanValues
    ShowSecrets    = $ShowSecrets
    Sarif          = $Sarif
    NoJson         = $NoJson
    NoHtml         = $NoHtml
    NoCsv          = $NoCsv
    Quiet          = $Quiet
}
# Only forward options the caller set, so the cmdlet's own defaults apply.
if ($OutputDirectory)  { $params['OutputDirectory']  = $OutputDirectory }
if ($IncludeExtension) { $params['IncludeExtension'] = $IncludeExtension }
if ($SuppressionFile)  { $params['SuppressionFile']  = $SuppressionFile }

$findings = @(Invoke-MBSecretScan @params)

if ($PassThru) { $findings }

if ($FailOnSeverity) {
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $hits = @($findings | Where-Object { $rank[$_.Severity] -le $rank[$FailOnSeverity] })
    if ($hits.Count -gt 0) {
        Write-Warning ("{0} finding(s) at or above {1} severity." -f $hits.Count, $FailOnSeverity)
        exit 1
    }
}
exit 0

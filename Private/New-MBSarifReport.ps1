function New-MBSarifReport {
    <#
    .SYNOPSIS
        Writes findings as a SARIF 2.1.0 log for code-scanning tooling.
    .DESCRIPTION
        Message text carries the (already redacted, unless -ShowSecrets) value,
        never the raw secret. Severity maps to SARIF level: Critical/High ->
        error, Medium -> warning, Low/Info -> note; the original severity is
        kept in result properties.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Findings,
        [object]$ScanInfo,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $level = @{ Critical = 'error'; High = 'error'; Medium = 'warning'; Low = 'note'; Info = 'note' }
    $Findings = @($Findings | Where-Object { $_ })

    $rules = @($Findings | Group-Object RuleId | ForEach-Object {
        $f = $_.Group[0]
        [ordered]@{
            id                   = $f.RuleId
            name                 = $f.RuleId
            shortDescription     = @{ text = [string]$f.RuleName }
            defaultConfiguration = @{ level = $level[$f.Severity] }
            properties           = @{ category = $f.Category; severity = $f.Severity }
        }
    })

    $results = @(foreach ($f in $Findings) {
        $loc = [ordered]@{ artifactLocation = @{ uri = ([string]$f.File).Replace('\', '/'); uriBaseId = 'SCANROOT' } }
        if ($f.Line -gt 0) { $loc.region = @{ startLine = [int]$f.Line } }
        [ordered]@{
            ruleId     = $f.RuleId
            level      = $level[$f.Severity]
            message    = @{ text = '{0}: {1}' -f $f.RuleName, $f.Value }
            locations  = @(@{ physicalLocation = $loc })
            properties = @{ severity = $f.Severity; category = $f.Category; context = $f.Context }
        }
    })

    $rootUri = ([System.Uri]::new(($ScanInfo.ScanRoot.TrimEnd('\', '/') + '/'))).AbsoluteUri
    $log = [ordered]@{
        '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'
        version   = '2.1.0'
        runs      = @(@{
            tool = @{ driver = @{
                name           = 'MicroBurstSecretsHunter'
                informationUri = 'https://github.com/NetSPI/MicroBurst'
                rules          = $rules
            } }
            originalUriBaseIds = @{ SCANROOT = @{ uri = $rootUri } }
            results            = $results
        })
    }
    $log | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $OutputPath -Encoding UTF8
}

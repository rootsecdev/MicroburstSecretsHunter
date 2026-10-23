function Read-MBSuppressionFile {
    <#
    .SYNOPSIS
        Loads and validates an analyst suppression file (JSON array).
    .DESCRIPTION
        Each entry may set RuleId, Category, File (wildcard on the relative
        path, '/' separated), Line and ValuePattern (regex on the unredacted
        value), plus a free-text Reason. An entry with no matching field would
        silently suppress every finding, so it is rejected.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $entries = @($raw | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        throw "Suppression file '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    $matchFields = 'RuleId','Category','File','Line','ValuePattern'
    $known       = $matchFields + 'Reason'
    $out = for ($i = 0; $i -lt $entries.Count; $i++) {
        $e = $entries[$i]
        $names = @($e.PSObject.Properties.Name)
        foreach ($n in $names) {
            if ($known -notcontains $n) { Write-Warning "Suppression entry #$($i + 1): unknown field '$n' ignored." }
        }
        if (-not ($matchFields | Where-Object { $names -contains $_ -and "$($e.$_)" -ne '' })) {
            throw "Suppression entry #$($i + 1) sets none of $($matchFields -join ', ') and would suppress every finding."
        }
        $re = $null
        if ($e.ValuePattern) {
            try { $re = [regex]::new([string]$e.ValuePattern) }
            catch { throw "Suppression entry #$($i + 1): invalid ValuePattern regex: $($_.Exception.Message)" }
        }
        [PSCustomObject]@{
            RuleId   = [string]$e.RuleId
            Category = [string]$e.Category
            File     = if ($e.File) { ([string]$e.File).Replace('\', '/') } else { '' }
            Line     = if ($null -ne $e.Line -and "$($e.Line)" -ne '') { [int]$e.Line } else { $null }
            Regex    = $re
        }
    }
    return @($out)
}

function Test-MBSuppressed {
    <#
    .SYNOPSIS
        True when a finding matches every field of any suppression entry.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($Finding, [object[]]$Suppressions)

    $file = ([string]$Finding.File).Replace('\', '/')
    foreach ($s in $Suppressions) {
        if ($s.RuleId   -and $s.RuleId   -ne $Finding.RuleId)   { continue }
        if ($s.Category -and $s.Category -ne $Finding.Category) { continue }
        if ($s.File     -and -not ($file -like $s.File))        { continue }
        if ($null -ne $s.Line -and $s.Line -ne $Finding.Line)   { continue }
        if ($s.Regex    -and -not $s.Regex.IsMatch([string]$Finding.RawValue)) { continue }
        return $true
    }
    return $false
}

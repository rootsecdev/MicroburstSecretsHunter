# Internal helper functions for MicroBurstSecretsHunter.

function Get-MBEntropy {
    <#
    .SYNOPSIS
        Shannon entropy (bits per character) of a string.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return 0.0 }

    $len = $Text.Length
    $counts = @{}
    foreach ($c in $Text.ToCharArray()) {
        if ($counts.ContainsKey($c)) { $counts[$c]++ } else { $counts[$c] = 1 }
    }

    $entropy = 0.0
    foreach ($n in $counts.Values) {
        $p = $n / $len
        $entropy += -$p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 2)
}

function Protect-MBValue {
    <#
    .SYNOPSIS
        Redacts a secret value for safe inclusion in reports, keeping a small
        prefix (and, for long values, a short suffix) so findings remain
        identifiable.
    .DESCRIPTION
        The revealed characters are budgeted at a quarter of the value length,
        capped at 4 leading + 2 trailing. Values of 8 characters or fewer are
        replaced wholesale with a fixed-width mask: a typical password is 8-14
        characters, where revealing a fixed 4+2 window exposed enough of the
        secret to reconstruct it (e.g. "P@ssw0rd" -> "P@ss**rd"). The fixed
        width also avoids disclosing the exact length of a short secret.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return '' }

    $v = $Value.Trim()

    # Scan-level toggle set by Invoke-MBSecretScan -ShowSecrets. Defaults to
    # redacting when unset (e.g. if the helper is called outside a scan).
    if ($null -ne $script:MBRedact -and -not $script:MBRedact) { return $v }

    $len = $v.Length
    if ($len -le 8) { return ('*' * 8) }

    # Never reveal more than a quarter of the value.
    $budget    = [int][Math]::Floor($len / 4)
    $keepStart = [Math]::Min(4, $budget)
    $keepEnd   = [Math]::Max(0, [Math]::Min(2, $budget - $keepStart))
    $maskLen   = [Math]::Max(4, [Math]::Min(10, $len - ($keepStart + $keepEnd)))

    $tail = if ($keepEnd -gt 0) { $v.Substring($len - $keepEnd) } else { '' }
    return $v.Substring(0, $keepStart) + ('*' * $maskLen) + $tail
}

function Get-MBContext {
    <#
    .SYNOPSIS
        Builds the display context for a finding: redacts first, truncates
        second.
    .DESCRIPTION
        Redaction is applied to the FULL line before any truncation, and to
        every secret value discovered on that line -- not just this finding's.
        Truncating first (as an earlier version did) left plaintext in the
        Context column whenever a match straddled or sat past the truncation
        boundary, because the subsequent string replacement no longer found the
        value. Redacting every value on the line also stops one finding's
        context from disclosing a neighbouring finding's secret.

        The surviving window is centred on this finding's own (redacted) value
        so the match stays visible in the report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Line,
        [string]$Value,
        [string[]]$AllValues = @(),
        [int]$Window = 200
    )

    $trimmed = $Line.Trim()
    $ctx     = $trimmed

    # Longest first, so a value that is a substring of a longer one cannot
    # corrupt the longer replacement.
    $targets = @(@($AllValues) + @($Value) |
        Where-Object { -not [string]::IsNullOrEmpty($_) } |
        Sort-Object -Property Length -Descending)

    $done = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($t in $targets) {
        if (-not $done.Add($t)) { continue }
        $ctx = $ctx.Replace($t, (Protect-MBValue $t))
    }

    if ($ctx.Length -le $Window) { return $ctx }

    # Centre the window on the redacted match (a quarter of the window ahead of
    # it) so surrounding context is preserved on both sides.
    $marker = if ([string]::IsNullOrEmpty($Value)) { '' } else { Protect-MBValue $Value }
    $at = if ($marker) { $ctx.IndexOf($marker, [System.StringComparison]::Ordinal) } else { 0 }
    if ($at -lt 0) {
        # This value was swallowed by the redaction of a longer value that
        # contained it, so its own marker is gone. Anchor on where the value sat
        # in the original line instead, scaled to the redacted length, rather
        # than falling back to offset 0 and showing unrelated padding.
        $rawAt = $trimmed.IndexOf($Value, [System.StringComparison]::Ordinal)
        $at = if ($rawAt -ge 0 -and $trimmed.Length -gt 0) {
            [int]([double]$rawAt / $trimmed.Length * $ctx.Length)
        } else { 0 }
    }

    $start = [Math]::Max(0, $at - [int]($Window / 4))
    $start = [Math]::Min($start, [Math]::Max(0, $ctx.Length - $Window))
    $len   = [Math]::Min($Window, $ctx.Length - $start)
    $slice = $ctx.Substring($start, $len)

    if ($start -gt 0)                    { $slice = '…' + $slice }
    if (($start + $len) -lt $ctx.Length) { $slice = $slice + '…' }
    return $slice
}

function Protect-MBCsvField {
    <#
    .SYNOPSIS
        Neutralizes spreadsheet formula injection in a CSV report field.
    .DESCRIPTION
        findings.csv carries content copied out of the audited environment
        (file paths, matched values, whole source lines) and is meant to be
        opened in Excel. A field beginning with =, +, -, @, tab or CR is
        interpreted as a formula by Excel and LibreOffice, so a value planted
        in the scanned dump could execute on the analyst's workstation.
        Prefixing with an apostrophe forces it to be read as text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value[0] -in '=', '+', '-', '@', "`t", "`r") { return "'" + $Value }
    return $Value
}

function Test-MBPlaceholder {
    <#
    .SYNOPSIS
        Returns $true when a candidate value is an obvious non-secret
        (placeholder, masked value, boolean, empty, etc.).
    .PARAMETER CodeContext
        Enable the heuristics that dismiss values looking like code
        expressions -- PowerShell variable references, parenthesised
        sub-expressions and Verb-Noun cmdlet calls. These overlap with real
        password shapes ("$ummer2026" is a valid variable reference AND a
        plausible password), so they only apply when the value was read from a
        file that actually contains code (a runbook, ARM template, Terraform
        config), not from a CSV value cell.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$Value,
        [switch]$CodeContext
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }

    $v = $Value.Trim().Trim('"').Trim("'").Trim()
    if ($v.Length -lt 4) { return $true }

    # All one repeated character (****, xxxx, ----, ....)
    if ($v -match '^(.)\1{2,}$') { return $true }

    # Common literal placeholders / non-secret values
    $placeholders = @(
        'null','none','n/a','na','nil','empty','true','false','yes','no',
        'notconfigured','not configured','notset','not set','notavailable',
        'not available','enabled','disabled','default','redacted','removed',
        'masked','hidden','unknown','example','changeme','your-password-here',
        'system','localhost','encrypted'
    )
    if ($placeholders -contains $v.ToLowerInvariant()) { return $true }

    # Template tokens and structured data, matched as balanced pairs so a
    # password merely containing '$' or '%' is not swallowed:
    # <password>, ${var}, %VAR%, {{x}}, JSON objects {..}, JSON arrays [..]
    # (?s) so multi-line JSON values in CSV cells are recognised too.
    if ($v -match '(?s)^<.*>$')     { return $true }   # <provide-at-deploy>
    if ($v -match '(?s)^\$\{.*\}$') { return $true }   # ${var}
    if ($v -match '^%[^%]*%$')      { return $true }   # %VAR%
    if ($v -match '(?s)^\{.*\}$')   { return $true }   # {json} / {{token}}
    if ($v -match '(?s)^\[.*\]$')   { return $true }   # [json array]

    # .NET type names / collection references — how complex object properties
    # (e.g. a VM scale set "Secrets" VaultSecretGroup list) serialize to CSV.
    if ($v -match '^(System|Microsoft|Azure|Newtonsoft)\.[A-Za-z0-9_.+`\[\]]+$') { return $true }
    if ($v -match '`\d\[') { return $true }   # generic type marker, e.g. List`1[...]

    # Dates / timestamps (ISO 8601 and common forms) are never secrets.
    if ($v -match '^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$') { return $true }
    if ($v -match '^\d{1,2}/\d{1,2}/\d{2,4}([ T]\d{1,2}:\d{2}(:\d{2})?( ?[AP]M)?)?$') { return $true }

    # Template / markup references that no password could plausibly be. Safe to
    # apply everywhere: these come from ARM and Logic App definitions where
    # "password" is a property name pointing at an expression.
    if ($v -match '^@\{')          { return $true }   # @{ splat / hashtable
    if ($v -match '^@[A-Za-z]+\(') { return $true }   # Logic App  @body( @parameters(
    if ($v -match '^\[[A-Za-z]+\(') { return $true }  # ARM        [parameters( [concat(

    # Code expressions. These shapes are ambiguous with real secrets, so they
    # only apply to values read out of code-bearing files. Applying them
    # everywhere discarded genuine passwords beginning with '$'.
    if ($CodeContext) {
        # $var, $global:x, $env:y, $a.b, $a[0]
        if ($v -match '^\$(\w+:)?[A-Za-z_][\w]*(\.[\w]+|\[[^\]]*\])*$') { return $true }
        # (expression) e.g. (-join $x)
        if ($v -match '^\(') { return $true }
        # Verb-Noun cmdlet call
        if ($v -match '^(Get|Set|New|Add|Remove|Clear|Import|Export|Invoke|Start|Stop|Restart|Test|Connect|Disconnect|Update|Convert|ConvertTo|ConvertFrom|Select|Where|Sort|Group|Measure|Compare|Format|Out|Write|Read|Show|Enable|Disable|Install|Uninstall|Register|Unregister|Find|Search|Resolve|Send|Receive|Request|Wait|Publish|Join|Split|Move|Copy|Rename|Mount|Expand|Initialize|Build|Deploy|Restore|Backup|Grant|Revoke)-[A-Z][A-Za-z0-9]*') { return $true }
    }

    # Pure punctuation / whitespace
    if ($v -match '^[\s\*x\-\._•·]+$') { return $true }

    return $false
}

function Test-MBIsGuid {
    <#
    .SYNOPSIS
        True if the value is a GUID (subscription/tenant/resource/object IDs
        are ubiquitous in Azure dumps and are not secrets).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value.Trim() -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Get-MBLineSegment {
    <#
    .SYNOPSIS
        Splits an over-long line into overlapping windows for regex scanning.
    .DESCRIPTION
        Minified single-line JSON is normal in Azure exports (ARM templates,
        Logic App definitions, app-setting blobs), and a line of tens of
        kilobytes is not unusual. Truncating such a line at a fixed length --
        as an earlier version did -- silently dropped every secret past the cut
        with no warning. Windows overlap so a match straddling a boundary is
        still found intact in the following window; duplicate hits from the
        overlap collapse in the scanner's de-duplication.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [string]$Line,
        [int]$MaxLength = 8000,
        [int]$Overlap = 500
    )

    if ([string]::IsNullOrEmpty($Line) -or $Line.Length -le $MaxLength) { return @($Line) }
    if ($Overlap -ge $MaxLength) { $Overlap = [int]($MaxLength / 2) }

    $out  = [System.Collections.Generic.List[string]]::new()
    $step = $MaxLength - $Overlap
    $pos  = 0
    while ($pos -lt $Line.Length) {
        $take = [Math]::Min($MaxLength, $Line.Length - $pos)
        $out.Add($Line.Substring($pos, $take))
        if (($pos + $take) -ge $Line.Length) { break }
        $pos += $step
    }
    return $out.ToArray()
}

function Get-MBLineNumber {
    <#
    .SYNOPSIS
        1-based line number of a character index within a string.
    .DESCRIPTION
        Counts newlines with IndexOf rather than materialising
        $Text.Substring(0, $Index) and splitting it, which allocated a copy of
        the whole prefix (up to -MaxFileSizeMB) plus an array of every line for
        each whole-file match.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([string]$Text, [int]$Index)

    if ([string]::IsNullOrEmpty($Text) -or $Index -le 0) { return 1 }

    $n = 1
    $p = $Text.IndexOf("`n")
    while ($p -ge 0 -and $p -lt $Index) {
        $n++
        $p = $Text.IndexOf("`n", $p + 1)
    }
    return $n
}

function Get-MBNameClassification {
    <#
    .SYNOPSIS
        Classifies a column header or variable name as a secret type.
    .DESCRIPTION
        Unlike the raw-line regexes (which need word boundaries), this matches
        the keyword anywhere inside a compound identifier such as
        "ServiceAccountPwd", "dbConnectionString" or "myStorageAccountKey".
        Returns a signature-shaped object, or $null when the name is not
        sensitive.
    #>
    [CmdletBinding()]
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    # Benign Azure AD / directory metadata fields whose names contain a
    # sensitive keyword but never hold a plaintext secret in a read-only dump
    # (these describe password *policy/state*, not the password itself).
    # Common in RBAC exports such as InheritedOwners.csv / InheritedContributors.csv.
    $benign = @(
        'force[_ -]?change[_ -]?password'
        'password[_ -]?profile'
        'password[_ -]?polic'
        'password[_ -]?expir'
        'password[_ -]?never[_ -]?expires'
        'password[_ -]?(not[_ -]?)?required'
        'password[_ -]?(last[_ -]?set|age|history|reset|strength)'
        'last[_ -]?password[_ -]?change'
        'pwd[_ -]?last[_ -]?set'
        'days[_ -]?(until|to)[_ -]?password'
        # Key Vault access-policy permission columns hold permission verbs
        # (Get, List, Set, ...), never the secret value itself.
        'permission'
    )
    foreach ($b in $benign) { if ($Name -imatch $b) { return $null } }

    # Ordered most-specific first; first match wins.
    $rules = @(
        @{ Re = 'connection[_ -]?string|connstr';                         Id = 'CSV_CONNSTR';   Disp = 'Connection string'; Category = 'ConnectionString'; Severity = 'High'   }
        @{ Re = 'client[_ -]?secret|clientsecret';                        Id = 'CSV_SECRET';    Disp = 'Client secret';     Category = 'Secret';           Severity = 'High'   }
        @{ Re = 'password|passwd|pwd|passphrase';                         Id = 'CSV_PASSWORD';  Disp = 'Password';          Category = 'Password';         Severity = 'High'   }
        @{ Re = 'account[_ -]?key|access[_ -]?key|api[_ -]?key|apikey|primary[_ -]?key|secondary[_ -]?key|subscription[_ -]?key|shared[_ -]?access[_ -]?key'; Id = 'CSV_KEY'; Disp = 'API / access key'; Category = 'Key'; Severity = 'High' }
        @{ Re = 'secret';                                                 Id = 'CSV_SECRET';    Disp = 'Secret';            Category = 'Secret';           Severity = 'High'   }
        @{ Re = 'sas[_ -]?token|shared[_ -]?access[_ -]?signature|\bsas\b'; Id = 'CSV_SAS';     Disp = 'SAS token';         Category = 'Token';            Severity = 'High'   }
        @{ Re = 'token|bearer';                                           Id = 'CSV_TOKEN';     Disp = 'Token';             Category = 'Token';            Severity = 'Medium' }
        @{ Re = 'credential|\bcred\b';                                    Id = 'CSV_CRED';      Disp = 'Credential';        Category = 'Password';         Severity = 'Medium' }
    )

    foreach ($r in $rules) {
        if ($Name -imatch $r.Re) {
            return [PSCustomObject]@{
                Id       = $r.Id
                Name     = "$($r.Disp) (CSV Name/Value pair)"
                Category = $r.Category
                Severity = $r.Severity
            }
        }
    }
    return $null
}

function Get-MBValueClassification {
    <#
    .SYNOPSIS
        Classifies a cell VALUE as a likely secret based on its content alone,
        for the optional value-side scan (-ScanValues).
    .DESCRIPTION
        Used to catch secrets stored under an innocuous name (e.g.
        "Config1 = P@ssw0rd") that neither the name classifier nor the
        keyword regexes would flag. Deliberately conservative and Low severity:

          - Password-like: 8-64 chars, no whitespace, contains a strong special
            character (!@#$%^&* etc.) plus letters and another class. This avoids
            flagging resource identifiers like "Standard_D2s_v3" (whose only
            symbols are _ - .).
          - High-entropy: >= 16 chars, mixed letters+digits or base64 markers,
            Shannon entropy >= MinEntropy.

        Returns a signature-shaped object or $null.
    #>
    [CmdletBinding()]
    param([string]$Value, [double]$MinEntropy = 4.0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().Trim('"').Trim("'").Trim()
    if ($v.Length -lt 8 -or $v.Length -gt 200) { return $null }
    if ($v -match '\s') { return $null }       # secrets rarely contain whitespace
    if ($v -match '[\\/]') { return $null }    # path / URL / resource ID, not a discrete secret
                                               # (base64 keys with '/' are caught by specialized rules)

    $lower = $v -cmatch '[a-z]'
    $upper = $v -cmatch '[A-Z]'
    $digit = $v -cmatch '[0-9]'
    # "strong" symbols only — _ . - are common in identifiers and excluded.
    $strong = $v -cmatch '[!@#$%^&*()+=?<>{}\[\]~|:;,]'
    $hasLetter = $lower -or $upper

    if ($v.Length -le 64 -and $strong -and $hasLetter -and ($digit -or ($lower -and $upper))) {
        return [PSCustomObject]@{
            Id       = 'CSV_VALUE_PWDLIKE'
            Name     = 'Possible secret (complex value under non-sensitive name)'
            Category = 'Password'
            Severity = 'Low'
        }
    }

    if ($v.Length -ge 16 -and ($strong -or ($digit -and $hasLetter))) {
        $ent = Get-MBEntropy $v
        if ($ent -ge $MinEntropy) {
            return [PSCustomObject]@{
                Id       = 'CSV_VALUE_ENTROPY'
                Name     = "Possible secret (high-entropy value, entropy $ent)"
                Category = 'Heuristic'
                Severity = 'Low'
            }
        }
    }

    return $null
}

function Get-MBCsvFinding {
    <#
    .SYNOPSIS
        Structured scan of a CSV/TSV: pairs a sensitive column/variable name
        with the value held in another column.
    .DESCRIPTION
        Handles two layouts common in Get-AzDomainInfo output:

          Mode A (Name/Value pair) - automation variables and app settings
            exported as rows of  Name,Value[,Encrypted]. The secret lives in
            the Value column and is named by the Name column. Rows flagged
            Encrypted=True are skipped (the value is not plaintext).

          Mode B (sensitive column header) - tables where a column header is
            itself sensitive (e.g. a "Password" or "StorageKey" column); every
            non-placeholder cell in that column is reported.

        Values that already match a high-confidence specialized signature
        (connection strings, storage keys, SAS, etc.) are left for the raw-line
        pass, which redacts them more precisely.

        Returns: [PSCustomObject] with .Parsed (bool) and .Findings (array of
        @{ Sig; Value; Row; Context }), where Row is the 1-based physical file
        line of the record (accounting for multi-line quoted cells).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [object[]]$SpecializedRegex = @(),
        [bool]$ScanValues = $false,
        [double]$MinEntropy = 4.0
    )

    $out = [PSCustomObject]@{ Parsed = $false; Findings = @() }

    $delimiter = if ([System.IO.Path]::GetExtension($FilePath).ToLowerInvariant() -eq '.tsv') { "`t" } else { ',' }
    try {
        $rows = @(Import-Csv -LiteralPath $FilePath -Delimiter $delimiter -ErrorAction Stop)
    } catch {
        return $out   # could not parse as CSV; caller falls back to raw scan
    }
    $out.Parsed = $true
    if ($rows.Count -eq 0) { return $out }

    # Map each data record to its starting physical line. A quoted field may span
    # several physical lines (common in Get-AzDomainInfo output, e.g. a JSON
    # "Secrets" cell), so the logical record index is not the file line. Track
    # double-quote parity across lines: a physical line that begins while not
    # inside an open quote starts a new record. starts[0] is the header.
    $lineMap = $null
    try {
        $physLines = [System.IO.File]::ReadAllLines($FilePath)
        $starts    = [System.Collections.Generic.List[int]]::new()
        $inQuotes  = $false
        for ($ln = 0; $ln -lt $physLines.Count; $ln++) {
            if (-not $inQuotes) { $starts.Add($ln + 1) }
            $qc = 0
            foreach ($ch in $physLines[$ln].ToCharArray()) { if ($ch -eq '"') { $qc++ } }
            if (($qc % 2) -ne 0) { $inQuotes = -not $inQuotes }
        }
        # Only trust the map if the record count lines up with Import-Csv's;
        # otherwise fall back to header+row arithmetic below.
        if (($starts.Count - 1) -eq $rows.Count) { $lineMap = $starts }
    } catch { $lineMap = $null }

    # Physical (1-based) file line for data record index $i.
    function Get-RowLine([int]$i) {
        if ($lineMap) { return $lineMap[$i + 1] }
        return $i + 2   # header is line 1, first data record is line 2
    }

    $cols = @($rows[0].PSObject.Properties.Name)

    $nameCol  = $cols | Where-Object { $_ -imatch '^(name|variable|variablename|key|keyname|setting|settingname|property|propertyname|parameter|parametername)$' } | Select-Object -First 1
    $valueCol = $cols | Where-Object { $_ -imatch '^(value|settingvalue|secretvalue|data|content|val)$' } | Select-Object -First 1
    $encCol   = $cols | Where-Object { $_ -imatch '^(encrypted|isencrypted|issecret)$' } | Select-Object -First 1

    $findings = [System.Collections.Generic.List[object]]::new()

    function Test-SpecializedMatch([string]$v) {
        foreach ($re in $SpecializedRegex) { if ($re.IsMatch($v)) { return $true } }
        return $false
    }

    # ---- Mode A: Name/Value pairing ---- #
    if ($nameCol -and $valueCol) {
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $row = $rows[$i]
            $nm  = [string]$row.$nameCol
            $val = [string]$row.$valueCol

            if ($encCol) {
                $enc = [string]$row.$encCol
                if ($enc -imatch '^\s*(true|1|yes)\s*$') { continue }
            }
            if (Test-MBPlaceholder $val) { continue }
            if (Test-MBIsGuid $val) { continue }
            if (Test-SpecializedMatch $val) { continue }   # raw pass handles it better

            # Classify by the variable name; fall back to value-content
            # heuristics when -ScanValues is set (catches secrets under an
            # innocuous name).
            $sig = Get-MBNameClassification $nm
            if (-not $sig -and $ScanValues) {
                $sig = Get-MBValueClassification -Value $val -MinEntropy $MinEntropy
            }
            if (-not $sig) { continue }

            $findings.Add([PSCustomObject]@{
                Sig     = $sig
                Value   = $val
                Row     = (Get-RowLine $i)
                Context = ('{0} = {1}' -f $nm, (Protect-MBValue $val))
            })
        }
    }

    # ---- Mode B: sensitive column headers ---- #
    foreach ($c in $cols) {
        if ($c -eq $valueCol -or $c -eq $nameCol) { continue }
        $sig = Get-MBNameClassification $c
        if (-not $sig) { continue }
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $val = [string]$rows[$i].$c
            if (Test-MBPlaceholder $val) { continue }
            if (Test-MBIsGuid $val) { continue }
            if (Test-SpecializedMatch $val) { continue }

            $findings.Add([PSCustomObject]@{
                Sig     = $sig
                Value   = $val
                Row     = (Get-RowLine $i)
                Context = ('{0} = {1}' -f $c, (Protect-MBValue $val))
            })
        }
    }

    # ---- Mode C: value-side content scan on free-form tables (opt-in) ---- #
    # For tables with no clear Name/Value pairing, inspect every cell's content
    # so an obfuscated secret in any column is still surfaced (Low severity).
    if ($ScanValues -and -not ($nameCol -and $valueCol)) {
        for ($i = 0; $i -lt $rows.Count; $i++) {
            foreach ($c in $cols) {
                if (Get-MBNameClassification $c) { continue }   # Mode B handled it
                $val = [string]$rows[$i].$c
                if (Test-MBPlaceholder $val) { continue }
                if (Test-MBIsGuid $val) { continue }
                if (Test-SpecializedMatch $val) { continue }

                $sig = Get-MBValueClassification -Value $val -MinEntropy $MinEntropy
                if (-not $sig) { continue }

                $findings.Add([PSCustomObject]@{
                    Sig     = $sig
                    Value   = $val
                    Row     = (Get-RowLine $i)
                    Context = ('{0} = {1}' -f $c, (Protect-MBValue $val))
                })
            }
        }
    }

    $out.Findings = $findings.ToArray()
    return $out
}

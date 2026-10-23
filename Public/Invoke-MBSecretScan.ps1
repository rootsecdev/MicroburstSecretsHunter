function Invoke-MBSecretScan {
    <#
    .SYNOPSIS
        Scans a MicroBurst Get-AzDomainInfo dump (or any folder of text files)
        for plaintext passwords, keys, connection strings and other secrets.

    .DESCRIPTION
        Recursively reads text-like files under -Path and evaluates every line
        against a set of Azure-aware detection signatures (see Get-MBSignature),
        plus an optional high-entropy heuristic. Azure noise such as GUIDs,
        resource IDs and redacted placeholders is filtered to reduce false
        positives.

        Findings are emitted as objects, printed as a color-coded console
        summary, and (by default) written to CSV, JSON and a self-contained
        HTML report (optionally SARIF). Secret values are redacted in all output so the reports are
        safe to share with a client.

        Designed for read-only audit use against output you already collected
        with MicroBurst.

    .PARAMETER Path
        Root folder of the MicroBurst output to scan.

    .PARAMETER OutputDirectory
        Where to write the CSV / HTML reports. Defaults to a timestamped folder
        under the current location. Must not be the scan root itself (that
        would exclude every file from the scan); a folder nested inside the
        scan root is allowed but warned about.

    .PARAMETER IncludeEntropy
        Enable the high-entropy heuristic pass, which emits Low-severity
        "possible secret" findings for random-looking strings the signatures
        didn't match. Off by default (these are noisy); turn it on for a
        deeper, higher-recall sweep.

    .PARAMETER MinEntropy
        Minimum Shannon entropy (bits/char) for the heuristic pass. Default 4.0.

    .PARAMETER MaxFileSizeMB
        Skip files larger than this (default 50 MB) to avoid runaway reads.
        Skipped files are reported as a warning and counted in the summary.

    .PARAMETER IncludeExtension
        Override the default set of text-like extensions to scan. A leading dot
        is optional ('csv' and '.csv' are equivalent).

    .PARAMETER ScanValues
        Also inspect the CONTENT of CSV value cells (not just their column /
        variable names). Catches secrets stored under an innocuous name
        (e.g. "Config1 = P@ssw0rd") using password-complexity and entropy
        heuristics. Higher recall, more false positives — findings are Low
        severity. Off by default.

    .PARAMETER ShowSecrets
        Emit UNREDACTED secret values in all output (objects, console, CSV,
        HTML) to speed up triage of false positives. The reports become
        sensitive credential material — handle and delete accordingly.
        Off by default (values are redacted).

    .PARAMETER SuppressionFile
        JSON file of known false positives to drop from the results. It is an
        array of objects; a finding is suppressed when it matches EVERY field an
        entry specifies:

            RuleId        exact rule id            (e.g. "GENERIC_PASSWORD")
            Category      exact category           (e.g. "Heuristic")
            File          wildcard on the relative path, '/' separated
                          (e.g. "*/Runbooks/*.ps1")
            Line          exact line number
            ValuePattern  regex tested against the UNREDACTED value
            Reason        free text, ignored by matching

        An entry must set at least one matching field. The suppressed count is
        shown in the console summary and the reports.

    .PARAMETER Sarif
        Also write findings.sarif (SARIF 2.1.0) for code-scanning tools.

    .PARAMETER NoJson
        Do not write findings.json.

    .PARAMETER NoCsv
        Do not write the CSV report.

    .PARAMETER NoHtml
        Do not write the HTML report.

    .PARAMETER Quiet
        Suppress the console summary (objects are still returned).

    .EXAMPLE
        Invoke-MBSecretScan -Path .\MicroBurst-2026 -Verbose

    .EXAMPLE
        Invoke-MBSecretScan -Path .\dump -OutputDirectory .\report -IncludeEntropy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Container) { $true }
            else { throw "Path '$_' does not exist or is not a folder." }
        })]
        [string]$Path,

        [string]$OutputDirectory,

        [switch]$IncludeEntropy,

        [ValidateRange(0.0, 8.0)]
        [double]$MinEntropy = 4.0,

        [ValidateRange(1, 1048576)]
        [int]$MaxFileSizeMB = 50,

        [string[]]$IncludeExtension = @(
            '.csv','.tsv','.txt','.json','.xml','.config','.ini','.env',
            '.yaml','.yml','.log','.ps1','.psd1','.psm1','.html','.htm',
            '.md','.cfg','.conf','.properties','.tf','.tfvars',
            # Text-based key/cert containers: scanned so the multi-line
            # PRIVATE_KEY_BLOCK rule (Critical) fires on the PEM content,
            # not just the High "key file present" rule. Binary containers
            # (.pfx/.p12/.der/.jks) stay out — they're caught by presence only.
            '.pem','.key','.crt','.cer',''
        ),

        [switch]$ScanValues,

        [switch]$ShowSecrets,

        [ValidateScript({
            if (Test-Path -LiteralPath $_ -PathType Leaf) { $true }
            else { throw "Suppression file '$_' does not exist." }
        })]
        [string]$SuppressionFile,

        [switch]$Sarif,
        [switch]$NoJson,
        [switch]$NoCsv,
        [switch]$NoHtml,
        [switch]$Quiet
    )

    $ErrorActionPreference = 'Stop'
    $scanStart = Get-Date
    $root = (Resolve-Path -LiteralPath $Path).Path

    # Module-scoped redaction toggle honored by Protect-MBValue everywhere.
    # Reset in the finally block below so a -ShowSecrets run cannot leave the
    # module in an unredacted state for the rest of the session.
    $script:MBRedact = -not $ShowSecrets

    try {
        if (-not $OutputDirectory) {
            $stamp = $scanStart.ToString('yyyyMMdd-HHmmss')
            $OutputDirectory = Join-Path (Get-Location).Path "MBSecretScan-$stamp"
        }
        $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
        $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

        # The scanner never scans its own output, so an output directory equal to
        # the scan root excludes every file and reports a false all-clear.
        $sep = [System.IO.Path]::DirectorySeparatorChar
        $rootPrefix = $root.TrimEnd('\','/') + $sep
        if ($OutputDirectory.TrimEnd('\','/').Equals($root.TrimEnd('\','/'), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("OutputDirectory '$OutputDirectory' is the same folder as -Path. " +
                   "Report output is excluded from the scan, so this would report zero findings " +
                   "regardless of content. Choose an output folder outside the scan root.")
        }
        if ($OutputDirectory.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning ("OutputDirectory is inside the scan root; files already in " +
                           "'$OutputDirectory' will be excluded from this scan.")
        }

        # Mark the folder as scanner output so later runs whose scan root
        # contains it (e.g. two runs from inside the dump folder with the
        # default output location) skip it instead of re-reading old reports.
        $markerName = '.mbsecretscan-output'
        try {
            Set-Content -LiteralPath (Join-Path $OutputDirectory $markerName) -Encoding UTF8 ``
                -Value 'Created by MicroBurstSecretsHunter. Folders holding this file are excluded from scans.'
        } catch { Write-Verbose "Could not write output marker: $_" }

        $suppressions = @()
        if ($SuppressionFile) { $suppressions = @(Read-MBSuppressionFile -Path $SuppressionFile) }

        Write-Verbose "Scanning : $root"
        Write-Verbose "Report to: $OutputDirectory"

        # --- Compile signatures ------------------------------------------------ #
        # IgnoreCase is the default because most rules key off a keyword whose
        # casing varies ("AccountKey", "accountkey"). Rules whose credential format
        # is itself case-sensitive opt out via CaseSensitive — applying IgnoreCase
        # to those made e.g. "akiaijklmnopqrstuvwx" match the AWS key rule.
        $reCompiled = [System.Text.RegularExpressions.RegexOptions]::Compiled
        $reIgnore   = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        $signatures = foreach ($s in Get-MBSignature) {
            $opts = if ($s.CaseSensitive) { $reCompiled } else { $reCompiled -bor $reIgnore }
            [PSCustomObject]@{
                Id         = $s.Id
                Name       = $s.Name
                Category   = $s.Category
                Severity   = $s.Severity
                ValueGroup = $s.ValueGroup
                MultiLine  = [bool]$s.MultiLine
                CaseSensitive = [bool]$s.CaseSensitive
                # Absent Redact means "redact" — only a rule that explicitly opts
                # out (a PEM header, a file name) is shown verbatim.
                Redact     = ($null -eq $s.Redact -or [bool]$s.Redact)
                Regex      = [regex]::new($s.Pattern, $opts)
            }
        }
        $singleLineSigs = @($signatures | Where-Object { -not $_.MultiLine })
        $multiLineSigs  = @($signatures | Where-Object { $_.MultiLine })
        # One alternation of every single-line rule, evaluated once per segment.
        # Most lines in a dump match nothing; rejecting them with a single
        # IsMatch avoids running each rule's loop in PowerShell. Matching is
        # equivalent to "any rule matches": case-sensitive rules keep their
        # semantics via a scoped (?-i:...) group.
        $prefilter = [regex]::new(
            (($singleLineSigs | ForEach-Object {
                if ($_.CaseSensitive) { '(?-i:' + $_.Regex.ToString() + ')' }
                else                  { '(?:'   + $_.Regex.ToString() + ')' }
            }) -join '|'),
            ($reCompiled -bor $reIgnore))
        # High-confidence patterns used to defer structured-CSV values to the raw
        # pass (which redacts the precise value rather than the whole cell).
        $specializedRegex = @($singleLineSigs | Where-Object { $_.Id -notlike 'GENERIC_*' } | ForEach-Object { $_.Regex })
        # Note: '/' is deliberately excluded so Azure resource-ID paths are split
        # into short segments (and embedded GUIDs isolated) rather than flagged as
        # one long high-entropy token. Real base64 keys are caught by dedicated rules.
        $entropyToken   = [regex]::new('[A-Za-z0-9+=_-]{20,}',
                            [System.Text.RegularExpressions.RegexOptions]::Compiled)

        # Regex window for a single line, and the overlap between consecutive
        # windows (must exceed the longest value any rule can capture — currently
        # GENERIC_TOKEN at 400 chars — so no match is lost across a boundary).
        $maxLineLength = 8000
        $lineOverlap   = 500

        # --- Gather files ------------------------------------------------------ #
        $incExt = @{}
        foreach ($e in $IncludeExtension) {
            if ($null -eq $e) { continue }
            $k = $e.Trim().ToLowerInvariant()
            # Accept 'csv' as well as '.csv'; '' keeps meaning "no extension".
            if ($k -and -not $k.StartsWith('.')) { $k = '.' + $k }
            $incExt[$k] = $true
        }
        $maxBytes = [long]$MaxFileSizeMB * 1MB

        # Exclude only files genuinely *inside* the output directory. Compare against
        # the path plus a trailing separator so a sibling that merely shares the name
        # prefix (e.g. output '…/MBScan', file '…/MBScan-old/x') isn't wrongly skipped.
        $outPrefix = $OutputDirectory.TrimEnd('\','/') + $sep
        $allFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.FullName.StartsWith($outPrefix, [StringComparison]::OrdinalIgnoreCase) })

        # Earlier scanner output inside the scan root: folders carrying the
        # marker file, plus default-named folders from versions that predate
        # the marker. Re-scanning them reports the previous run's findings as
        # new ones (and, after a -ShowSecrets run, re-ingests plaintext). The
        # scan root itself is never excluded: pointing -Path at an old report
        # folder is deliberate.
        $rootTrim = $root.TrimEnd('\','/')
        $priorOut = @(@(
            $allFiles | Where-Object { $_.Name -eq $markerName } | ForEach-Object { $_.DirectoryName }
            $allFiles | Where-Object {
                $_.Name -in 'findings.csv','report.html' -and $_.Directory.Name -match '^MBSecretScan-\d{8}-\d{6}$'
            } | ForEach-Object { $_.DirectoryName }
        ) | Where-Object { -not $_.TrimEnd('\','/').Equals($rootTrim, [StringComparison]::OrdinalIgnoreCase) } |
            Sort-Object -Unique)
        if ($priorOut.Count -gt 0) {
            Write-Warning ("Skipping {0} earlier scanner output folder(s) inside the scan root: {1}" -f `
                $priorOut.Count, (($priorOut | ForEach-Object { $_.Substring($root.Length).TrimStart('\','/') }) -join ', '))
            $priorPrefixes = @($priorOut | ForEach-Object { $_.TrimEnd('\','/') + $sep })
            $allFiles = @($allFiles | Where-Object {
                $full = $_.FullName
                -not ($priorPrefixes | Where-Object { $full.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })
            })
        }

        $wanted = @($allFiles | Where-Object { $incExt.ContainsKey($_.Extension.ToLowerInvariant()) })
        $files        = @($wanted | Where-Object { $_.Length -le $maxBytes })
        $skippedLarge = @($wanted | Where-Object { $_.Length -gt $maxBytes })
        $unreadable   = [System.Collections.Generic.List[string]]::new()

        # A silently skipped file reads as "nothing found here". Say so out loud.
        if ($skippedLarge.Count -gt 0) {
            Write-Warning ("{0} file(s) exceed -MaxFileSizeMB ({1} MB) and were NOT scanned:" -f `
                $skippedLarge.Count, $MaxFileSizeMB)
            foreach ($sf in ($skippedLarge | Select-Object -First 10)) {
                Write-Warning ("  {0} ({1:N1} MB)" -f `
                    $sf.FullName.Substring($root.Length).TrimStart('\','/'), ($sf.Length / 1MB))
            }
            if ($skippedLarge.Count -gt 10) {
                Write-Warning ("  ... and {0} more." -f ($skippedLarge.Count - 10))
            }
        }

        # Certificate / key material files are findings just by existing.
        # Containers that normally hold a private key are High; .cer/.crt/.der
        # are usually public certificates, so they are Low (a PEM private key
        # inside one is still caught as Critical by PRIVATE_KEY_BLOCK).
        $keyFileExt        = @('.pfx','.p12','.pem','.key','.jks','.keystore','.ppk')
        $publicCertFileExt = @('.cer','.crt','.der')

        # Files that plausibly contain code, where a value shaped like a PowerShell
        # variable or a cmdlet call really is an expression rather than a secret.
        $codeExt = @{}
        foreach ($e in @('.ps1','.psm1','.psd1','.json','.xml','.config','.tf','.tfvars',
                         '.yaml','.yml','.html','.htm','.md')) { $codeExt[$e] = $true }

        $findings = [System.Collections.Generic.List[object]]::new()
        $seen     = [System.Collections.Generic.Dictionary[string,int]]::new()
        $sevRank  = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
        $keywordRule = '^(GENERIC_|ARM_PARAM_|CSV_|HIGH_ENTROPY)'

        function Add-Finding {
            param($File, [int]$Line, $Sig, [string]$Value, [string]$Context, [string]$Note)
            $rel = $File.FullName.Substring($root.Length).TrimStart('\','/')
            # A rule may opt out of redaction when its "value" is a label rather
            # than a secret (a PEM header line, a certificate file name); masking
            # those only made the report unreadable.
            $noRedact = ($null -ne $Sig.PSObject.Properties['Redact']) -and (-not $Sig.Redact)
            $shown = if ($noRedact) { $Value } else { Protect-MBValue $Value }
            # One finding per secret per line: the same value matched by several
            # rules (a storage connection string AND the bare 88-char key, a SQL
            # connection string AND the generic password rule) collapses to the
            # highest-severity rule. On a tie a format-specific rule (AZ_AAD_*,
            # SQL_CONNSTR_PWD, ...) beats a keyword-driven one (GENERIC_*,
            # ARM_PARAM_*, CSV_*), since its name says what the secret is;
            # otherwise the first-added is kept. Keyed on the raw value so dedup
            # is stable regardless of -ShowSecrets.
            $key = '{0}|{1}|{2}' -f $rel, $Line, $Value.Trim()
            $finding = [PSCustomObject]@{
                Severity     = $Sig.Severity
                Category     = $Sig.Category
                RuleId       = $Sig.Id
                RuleName     = $Sig.Name
                File         = $rel
                FullPath     = $File.FullName
                Line         = $Line
                Value        = $shown
                Context      = $Context
                Note         = $Note
                RawValue     = $Value
            }
            $idx = 0
            if ($seen.TryGetValue($key, [ref]$idx)) {
                $prev    = $findings[$idx]
                $newRank = $sevRank[$Sig.Severity]
                $oldRank = $sevRank[$prev.Severity]
                if ($newRank -lt $oldRank -or
                    ($newRank -eq $oldRank -and $prev.RuleId -match $keywordRule -and $Sig.Id -notmatch $keywordRule)) {
                    $findings[$idx] = $finding
                }
                return
            }
            $seen[$key] = $findings.Count
            $findings.Add($finding)
        }

        $fileCount = 0
        foreach ($file in $files) {
            $fileCount++
            if (-not $Quiet) {
                Write-Progress -Activity 'Scanning MicroBurst output' `
                    -Status "$fileCount / $($files.Count): $($file.Name)" `
                    -PercentComplete (($fileCount / [Math]::Max(1,$files.Count)) * 100)
            }

            $ext    = $file.Extension.ToLowerInvariant()
            $isCode = $codeExt.ContainsKey($ext)

            # ---- structured CSV / TSV column pairing ---- #
            # Runs first so its column-aware findings win over generic raw-line
            # matches for the same secret. Catches secrets the regexes miss, e.g.
            # an automation variable named "ServiceAccountPwd" whose value sits in
            # a separate Value column.
            if ($ext -eq '.csv' -or $ext -eq '.tsv') {
                $csvResult = Get-MBCsvFinding -FilePath $file.FullName -SpecializedRegex $specializedRegex `
                    -ScanValues:$ScanValues -MinEntropy $MinEntropy
                foreach ($cf in $csvResult.Findings) {
                    # $cf.Row is already the physical (1-based) file line of the record.
                    Add-Finding -File $file -Line $cf.Row -Sig $cf.Sig `
                        -Value $cf.Value -Context $cf.Context -Note 'CSV column pairing'
                }
            }

            # ---- read once ---- #
            # The whole file is read a single time and serves both the
            # multi-line rules and the per-line pass. (A lazy ReadLines
            # enumeration could also throw mid-loop, outside any handler, and
            # abort the entire scan on one bad file.)
            try { $rawText = [System.IO.File]::ReadAllText($file.FullName) }
            catch {
                Write-Verbose "Skipped (unreadable): $($file.FullName) - $($_.Exception.Message)"
                $unreadable.Add($file.FullName.Substring($root.Length).TrimStart('\','/'))
                continue
            }
            if ([string]::IsNullOrEmpty($rawText)) { continue }

            # ---- multi-line / whole-file rules (PEM blocks, ARM parameters) ---- #
            foreach ($sig in $multiLineSigs) {
                # Every match, not just the first: a single file can hold
                # several PEM blocks (a bundle, a concatenated chain).
                foreach ($m in $sig.Regex.Matches($rawText)) {
                    $g = if ($sig.ValueGroup -gt 0 -and $m.Groups.Count -gt $sig.ValueGroup) {
                        $m.Groups[$sig.ValueGroup]
                    } else { $m }
                    $val = $g.Value
                    if (Test-MBPlaceholder -Value $val -CodeContext:$isCode) { continue }
                    if (Test-MBIsGuid $val) { continue }

                    # Report on, and take context from, the line the value sits on.
                    $ls = $rawText.LastIndexOf("`n", [Math]::Max(0, $g.Index - 1)) + 1
                    if ($g.Index -eq 0) { $ls = 0 }
                    $le = $rawText.IndexOf("`n", $g.Index)
                    if ($le -lt 0) { $le = $rawText.Length }
                    $valueLine = $rawText.Substring($ls, $le - $ls).TrimEnd("`r")
                    $ctx = if ($sig.Redact) {
                        Get-MBContext -Line $valueLine -Value $val -AllValues @($val)
                    } else { $val }
                    Add-Finding -File $file -Line (Get-MBLineNumber -Text $rawText -Index $g.Index) -Sig $sig `
                        -Value $val -Context $ctx -Note 'Whole-file match'
                }
            }

            # ---- per-line rules + entropy ---- #
            $reader = [System.IO.StringReader]::new($rawText)
            $lineNo = 0
            while ($null -ne ($line = $reader.ReadLine())) {
                $lineNo++
                if ([string]::IsNullOrWhiteSpace($line)) { continue }

                # Over-long lines are scanned in overlapping windows instead of
                # being truncated, so a secret late in a minified JSON blob is
                # still found. Overlap duplicates collapse in Add-Finding's dedup.
                # (@() keeps a single short line an array; the helper is only
                # called when the line actually needs splitting.)
                $segments = @(if ($line.Length -le $maxLineLength) { $line } else {
                    Get-MBLineSegment -Line $line -MaxLength $maxLineLength -Overlap $lineOverlap
                })

                # Hits are collected for the whole line before any context is
                # rendered, so every secret on the line can be redacted out of
                # every finding's context. Context is cut from the FULL line,
                # not the window the hit came from: a window can end mid-secret,
                # and that cut fragment matches no complete value, so it would
                # survive redaction in a neighbouring finding's context.
                $lineHits = [System.Collections.Generic.List[object]]::new()

                for ($si = 0; $si -lt $segments.Count; $si++) {
                    $segment = $segments[$si]
                    if (-not $IncludeEntropy -and -not $prefilter.IsMatch($segment)) { continue }
                    $hits = [System.Collections.Generic.List[object]]::new()

                    # A match touching a window edge that the line continues past
                    # may be cut short; the overlapping neighbour window holds it
                    # whole, so the cut copy is dropped rather than reported as a
                    # second, truncated finding.
                    $cutLeft  = $si -gt 0
                    $cutRight = $si -lt ($segments.Count - 1)

                    foreach ($sig in $singleLineSigs) {
                        foreach ($m in $sig.Regex.Matches($segment)) {
                            if ($cutLeft  -and $m.Index -eq 0) { continue }
                            if ($cutRight -and ($m.Index + $m.Length) -ge $segment.Length) { continue }
                            $val = if ($sig.ValueGroup -gt 0 -and $m.Groups.Count -gt $sig.ValueGroup) {
                                $m.Groups[$sig.ValueGroup].Value
                            } else { $m.Value }

                            if (Test-MBPlaceholder -Value $val -CodeContext:$isCode) { continue }
                            if (Test-MBIsGuid $val) { continue }

                            $hits.Add([PSCustomObject]@{ Sig = $sig; Value = $val; Note = '' })
                        }
                    }

                    # ---- entropy heuristic (only when no stronger rule fired) ---- #
                    if ($IncludeEntropy -and $hits.Count -eq 0) {
                        foreach ($tm in $entropyToken.Matches($segment)) {
                            if ($cutLeft  -and $tm.Index -eq 0) { continue }
                            if ($cutRight -and ($tm.Index + $tm.Length) -ge $segment.Length) { continue }
                            $tok = $tm.Value
                            if ($tok.Length -lt 24) { continue }
                            if (Test-MBIsGuid $tok) { continue }
                            if (Test-MBPlaceholder -Value $tok -CodeContext:$isCode) { continue }

                            # Real key material mixes character classes. Plain camelCase
                            # identifiers (e.g. "networkSecurityGroups") are not secrets,
                            # so require either base64 markers or a digit+letter mix.
                            $hasDigit  = $tok -cmatch '[0-9]'
                            $hasLetter = $tok -cmatch '[A-Za-z]'
                            $hasB64    = $tok -cmatch '[+/=]'
                            if (-not ($hasB64 -or ($hasDigit -and $hasLetter))) { continue }

                            $ent = Get-MBEntropy $tok
                            if ($ent -lt $MinEntropy) { continue }

                            $hits.Add([PSCustomObject]@{
                                Sig = [PSCustomObject]@{
                                    Id = 'HIGH_ENTROPY'; Name = "High-entropy string (entropy $ent)"
                                    Category = 'Heuristic'; Severity = 'Low'; ValueGroup = 0
                                    MultiLine = $false; Redact = $true
                                }
                                Value = $tok
                                Note  = "Shannon entropy $ent bits/char"
                            })
                        }
                    }

                    # The entropy backstop stays per-segment: it only fires where
                    # no stronger rule matched in that window.
                    foreach ($h in $hits) { $lineHits.Add($h) }
                }

                if ($lineHits.Count -gt 0) {
                    $allValues = @($lineHits | ForEach-Object { $_.Value })
                    foreach ($hit in $lineHits) {
                        $ctx = Get-MBContext -Line $line -Value $hit.Value -AllValues $allValues
                        Add-Finding -File $file -Line $lineNo -Sig $hit.Sig `
                            -Value $hit.Value -Context $ctx -Note $hit.Note
                    }
                }
            }
            $reader.Dispose()
        }
        if (-not $Quiet) { Write-Progress -Activity 'Scanning MicroBurst output' -Completed }

        if ($unreadable.Count -gt 0) {
            Write-Warning ("{0} file(s) could not be read and were NOT scanned (run with -Verbose for the list)." -f $unreadable.Count)
        }

        # ---- certificate / key files present on disk ---- #
        # The value is the file name, not a secret — masking it made the
        # finding unreadable ("exported.pem" -> "exp*********").
        $keyFileSig = [PSCustomObject]@{
            Id = 'KEY_MATERIAL_FILE'; Name = 'Certificate / key material file'
            Category = 'PrivateKey'; Severity = 'High'; ValueGroup = 0
            MultiLine = $false; Redact = $false
        }
        $publicCertSig = [PSCustomObject]@{
            Id = 'CERT_FILE'; Name = 'Certificate file (usually public)'
            Category = 'Certificate'; Severity = 'Low'; ValueGroup = 0
            MultiLine = $false; Redact = $false
        }
        foreach ($f in $allFiles) {
            $fx = $f.Extension.ToLowerInvariant()
            if ($keyFileExt -contains $fx) {
                Add-Finding -File $f -Line 0 -Sig $keyFileSig -Value $f.Name `
                    -Context $f.Name -Note 'Key/cert file present in dump'
            } elseif ($publicCertFileExt -contains $fx) {
                Add-Finding -File $f -Line 0 -Sig $publicCertSig -Value $f.Name `
                    -Context $f.Name -Note 'Certificate file present in dump; confirm it holds no private key'
            }
        }

        # ---- analyst suppressions ---- #
        $suppressedCount = 0
        if ($suppressions.Count -gt 0) {
            $kept = [System.Collections.Generic.List[object]]::new()
            foreach ($fd in $findings) {
                if (Test-MBSuppressed -Finding $fd -Suppressions $suppressions) { $suppressedCount++ }
                else { $kept.Add($fd) }
            }
            $findings = $kept
            Write-Verbose "Suppressed $suppressedCount finding(s) via $SuppressionFile"
        }

        # --- order findings by severity --- #
        # RawValue only existed for dedup and suppression; it must not reach
        # the reports or the pipeline (Value is already the redacted form).
        $ordered = @($findings | Sort-Object `
            @{ Expression = { $sevRank[$_.Severity] } }, Category, File, Line |
            Select-Object -Property * -ExcludeProperty RawValue)

        # --- write reports --- #
        $scanInfo = [PSCustomObject]@{
            ScanRoot         = $root
            ScannedAt        = $scanStart
            DurationSec      = [Math]::Round(((Get-Date) - $scanStart).TotalSeconds, 1)
            FilesScanned     = $files.Count
            FilesTotal       = $allFiles.Count
            FilesSkippedSize = $skippedLarge.Count
            FilesUnreadable  = $unreadable.Count
            FindingCount     = $ordered.Count
            Suppressed       = $suppressedCount
            PriorOutputSkipped = $priorOut.Count
            EntropyEnabled   = [bool]$IncludeEntropy
            Unredacted       = [bool]$ShowSecrets
        }

        $csvColumns = 'Severity','Category','RuleId','RuleName','File','Line','Value','Context','Note'
        if (-not $NoCsv) {
            $csvPath = Join-Path $OutputDirectory 'findings.csv'
            if ($ordered.Count -gt 0) {
                # Fields carrying content from the scanned dump are escaped so a
                # planted value cannot execute as a formula when the report is
                # opened in Excel / LibreOffice.
                $ordered | Select-Object Severity, Category, RuleId,
                        @{ Name = 'RuleName'; Expression = { Protect-MBCsvField $_.RuleName } },
                        @{ Name = 'File';     Expression = { Protect-MBCsvField $_.File } },
                        Line,
                        @{ Name = 'Value';    Expression = { Protect-MBCsvField $_.Value } },
                        @{ Name = 'Context';  Expression = { Protect-MBCsvField $_.Context } },
                        @{ Name = 'Note';     Expression = { Protect-MBCsvField $_.Note } } |
                    Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            } else {
                # Header only, so tooling that imports the CSV still sees the schema.
                (($csvColumns | ForEach-Object { '"{0}"' -f $_ }) -join ',') |
                    Out-File -LiteralPath $csvPath -Encoding UTF8
            }
            $scanInfo | Add-Member -NotePropertyName CsvReport -NotePropertyValue $csvPath
        }

        if (-not $NoJson) {
            $jsonPath = Join-Path $OutputDirectory 'findings.json'
            [PSCustomObject]@{
                ScanInfo = $scanInfo
                Findings = @($ordered | Select-Object -Property ($csvColumns + 'FullPath'))
            } | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $jsonPath -Encoding UTF8
            $scanInfo | Add-Member -NotePropertyName JsonReport -NotePropertyValue $jsonPath
        }

        if ($Sarif) {
            $sarifPath = Join-Path $OutputDirectory 'findings.sarif'
            New-MBSarifReport -Findings $ordered -ScanInfo $scanInfo -OutputPath $sarifPath
            $scanInfo | Add-Member -NotePropertyName SarifReport -NotePropertyValue $sarifPath
        }

        if (-not $NoHtml) {
            $htmlPath = Join-Path $OutputDirectory 'report.html'
            New-MBHtmlReport -Findings $ordered -ScanInfo $scanInfo -OutputPath $htmlPath
            $scanInfo | Add-Member -NotePropertyName HtmlReport -NotePropertyValue $htmlPath
        }

        if (-not $Quiet) {
            Write-MBConsoleSummary -Findings $ordered -ScanInfo $scanInfo -OutputDirectory $OutputDirectory
        }

        # Emit findings to the pipeline.
        $ordered
    }
    finally {
        # Fail closed: whatever happened above, the module goes back to
        # redacting so a later call to Protect-MBValue cannot leak plaintext.
        $script:MBRedact = $true
    }
}

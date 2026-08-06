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
        summary, and (by default) written to a CSV and a self-contained HTML
        report. Secret values are redacted in all output so the reports are
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
                # Absent Redact means "redact" — only a rule that explicitly opts
                # out (a PEM header, a file name) is shown verbatim.
                Redact     = ($null -eq $s.Redact -or [bool]$s.Redact)
                Regex      = [regex]::new($s.Pattern, $opts)
            }
        }
        $singleLineSigs = @($signatures | Where-Object { -not $_.MultiLine })
        $multiLineSigs  = @($signatures | Where-Object { $_.MultiLine })
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
        $allFiles = Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.FullName.StartsWith($outPrefix, [StringComparison]::OrdinalIgnoreCase) }

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
        $keyFileExt = @('.pfx','.p12','.pem','.key','.cer','.crt','.der','.jks','.keystore','.ppk')

        # Files that plausibly contain code, where a value shaped like a PowerShell
        # variable or a cmdlet call really is an expression rather than a secret.
        $codeExt = @{}
        foreach ($e in @('.ps1','.psm1','.psd1','.json','.xml','.config','.tf','.tfvars',
                         '.yaml','.yml','.html','.htm','.md')) { $codeExt[$e] = $true }

        $findings = [System.Collections.Generic.List[object]]::new()
        $seen     = [System.Collections.Generic.HashSet[string]]::new()

        function Add-Finding {
            param($File, [int]$Line, $Sig, [string]$Value, [string]$Context, [string]$Note)
            $rel = $File.FullName.Substring($root.Length).TrimStart('\','/')
            # A rule may opt out of redaction when its "value" is a label rather
            # than a secret (a PEM header line, a certificate file name); masking
            # those only made the report unreadable.
            $noRedact = ($null -ne $Sig.PSObject.Properties['Redact']) -and (-not $Sig.Redact)
            $shown = if ($noRedact) { $Value } else { Protect-MBValue $Value }
            # Dedup on category (not rule id) so the same secret found two ways
            # (e.g. a structured CSV pair and a raw-line regex) collapses to one.
            # Use the raw value for the key so dedup is stable regardless of -ShowSecrets.
            $key = '{0}|{1}|{2}|{3}' -f $rel, $Line, $Sig.Category, $Value
            if (-not $seen.Add($key)) { return }
            $findings.Add([PSCustomObject]@{
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
            })
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

            # ---- multi-line / whole-file rules (private keys) ---- #
            $rawText = $null
            if ($multiLineSigs.Count -gt 0) {
                try { $rawText = [System.IO.File]::ReadAllText($file.FullName) } catch { $rawText = $null }
                if ($rawText) {
                    foreach ($sig in $multiLineSigs) {
                        # Every match, not just the first: a single file can hold
                        # several PEM blocks (a bundle, a concatenated chain).
                        foreach ($m in $sig.Regex.Matches($rawText)) {
                            $lineNo = Get-MBLineNumber -Text $rawText -Index $m.Index
                            Add-Finding -File $file -Line $lineNo -Sig $sig `
                                -Value $m.Value -Context $m.Value.Substring(0,[Math]::Min(60,$m.Value.Length)) `
                                -Note 'Whole-file match'
                        }
                    }
                }
            }

            # ---- per-line rules + entropy ---- #
            try { $lines = [System.IO.File]::ReadLines($file.FullName) }
            catch {
                Write-Verbose "Skipped (unreadable): $($file.FullName)"
                $unreadable.Add($file.FullName.Substring($root.Length).TrimStart('\','/'))
                continue
            }

            $lineNo = 0
            foreach ($line in $lines) {
                $lineNo++
                if ([string]::IsNullOrWhiteSpace($line)) { continue }

                # Over-long lines are scanned in overlapping windows instead of
                # being truncated, so a secret late in a minified JSON blob is
                # still found. Overlap duplicates collapse in Add-Finding's dedup.
                $segments = Get-MBLineSegment -Line $line -MaxLength $maxLineLength -Overlap $lineOverlap

                # Hits are collected for the whole line before any context is
                # rendered, so every secret on the line can be redacted out of
                # every finding's context — including a secret that a segment
                # boundary cut in half, which would otherwise survive as a raw
                # fragment in a neighbouring finding's context.
                $lineHits = [System.Collections.Generic.List[object]]::new()

                foreach ($segment in $segments) {
                    $hits = [System.Collections.Generic.List[object]]::new()

                    foreach ($sig in $singleLineSigs) {
                        foreach ($m in $sig.Regex.Matches($segment)) {
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
                    foreach ($h in $hits) {
                        $h | Add-Member -NotePropertyName Segment -NotePropertyValue $segment
                        $lineHits.Add($h)
                    }
                }

                if ($lineHits.Count -gt 0) {
                    $allValues = @($lineHits | ForEach-Object { $_.Value })
                    foreach ($hit in $lineHits) {
                        $ctx = Get-MBContext -Line $hit.Segment -Value $hit.Value -AllValues $allValues
                        Add-Finding -File $file -Line $lineNo -Sig $hit.Sig `
                            -Value $hit.Value -Context $ctx -Note $hit.Note
                    }
                }
            }
        }
        if (-not $Quiet) { Write-Progress -Activity 'Scanning MicroBurst output' -Completed }

        if ($unreadable.Count -gt 0) {
            Write-Warning ("{0} file(s) could not be read and were NOT scanned (run with -Verbose for the list)." -f $unreadable.Count)
        }

        # ---- certificate / key files present on disk ---- #
        foreach ($f in $allFiles) {
            if ($keyFileExt -contains $f.Extension.ToLowerInvariant()) {
                $sig = [PSCustomObject]@{
                    Id = 'KEY_MATERIAL_FILE'; Name = 'Certificate / key material file'
                    Category = 'PrivateKey'; Severity = 'High'; ValueGroup = 0
                    MultiLine = $false
                    # The value is the file name, not a secret — masking it made
                    # the finding unreadable ("exported.pem" -> "exp*********").
                    Redact = $false
                }
                Add-Finding -File $f -Line 0 -Sig $sig -Value $f.Name `
                    -Context $f.Name -Note 'Key/cert file present in dump'
            }
        }

        # --- order findings by severity --- #
        $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
        $ordered = $findings | Sort-Object `
            @{ Expression = { $sevRank[$_.Severity] } }, Category, File, Line

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
            EntropyEnabled   = [bool]$IncludeEntropy
            Unredacted       = [bool]$ShowSecrets
        }

        if (-not $NoCsv) {
            $csvPath = Join-Path $OutputDirectory 'findings.csv'
            if ($ordered) {
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
                '' | Out-File -LiteralPath $csvPath -Encoding UTF8
            }
            $scanInfo | Add-Member -NotePropertyName CsvReport -NotePropertyValue $csvPath
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

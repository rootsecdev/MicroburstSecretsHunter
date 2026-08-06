function Write-MBConsoleSummary {
    <#
    .SYNOPSIS
        Prints a color-coded summary of findings to the console.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Findings,
        [object]$ScanInfo,
        [string]$OutputDirectory
    )

    $sevColor = @{
        Critical = 'Red'; High = 'Magenta'; Medium = 'Yellow'
        Low = 'Cyan'; Info = 'Gray'
    }

    Write-Host ''
    Write-Host '==========================================================' -ForegroundColor DarkGray
    Write-Host '  MicroBurst Secrets Hunter - Scan Summary' -ForegroundColor White
    Write-Host '==========================================================' -ForegroundColor DarkGray
    if ($ScanInfo.Unredacted) {
        Write-Host '  !! SHOWING RAW SECRETS - output is UNREDACTED. Handle/delete reports as sensitive. !!' -ForegroundColor Black -BackgroundColor Yellow
        Write-Host ''
    }
    Write-Host ("  Scan root     : {0}" -f $ScanInfo.ScanRoot)
    Write-Host ("  Files scanned : {0} of {1}" -f $ScanInfo.FilesScanned, $ScanInfo.FilesTotal)
    # Skipped files are shown even when zero-suppressed elsewhere: an unscanned
    # file is a blind spot, and a silent one reads as "nothing found here".
    if ($ScanInfo.FilesSkippedSize -gt 0) {
        Write-Host ("  NOT scanned   : {0} file(s) over the size limit" -f $ScanInfo.FilesSkippedSize) `
            -ForegroundColor Yellow
    }
    if ($ScanInfo.FilesUnreadable -gt 0) {
        Write-Host ("  NOT scanned   : {0} unreadable file(s)" -f $ScanInfo.FilesUnreadable) `
            -ForegroundColor Yellow
    }
    Write-Host ("  Duration      : {0}s" -f $ScanInfo.DurationSec)
    Write-Host ("  Total findings: {0}" -f $ScanInfo.FindingCount)
    Write-Host ''

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Host '  No secrets detected. ' -ForegroundColor Green -NoNewline
        Write-Host '(Review manually — absence of detections is not proof of safety.)' -ForegroundColor DarkGray
        Write-Host ''
        return
    }

    # Counts by severity
    Write-Host '  Findings by severity:' -ForegroundColor White
    foreach ($sev in 'Critical','High','Medium','Low','Info') {
        $n = @($Findings | Where-Object Severity -eq $sev).Count
        if ($n -gt 0) {
            Write-Host ('    {0,-9} {1}' -f $sev, $n) -ForegroundColor $sevColor[$sev]
        }
    }
    Write-Host ''

    # Counts by category
    Write-Host '  Findings by category:' -ForegroundColor White
    $Findings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ('    {0,-16} {1}' -f $_.Name, $_.Count) -ForegroundColor Gray
    }
    Write-Host ''

    # Top findings (Critical/High) detail
    $top = @($Findings | Where-Object { $_.Severity -in 'Critical','High' } | Select-Object -First 25)
    if ($top.Count -gt 0) {
        Write-Host ('  Top findings (showing {0}):' -f $top.Count) -ForegroundColor White
        foreach ($f in $top) {
            $loc = if ($f.Line -gt 0) { "$($f.File):$($f.Line)" } else { $f.File }
            Write-Host ('  [{0}] ' -f $f.Severity) -ForegroundColor $sevColor[$f.Severity] -NoNewline
            Write-Host ('{0}' -f $f.RuleName) -ForegroundColor White
            Write-Host ('         {0}' -f $loc) -ForegroundColor DarkGray
            Write-Host ('         {0}' -f $f.Context) -ForegroundColor Gray
        }
        $remaining = $Findings.Count - $top.Count
        if ($remaining -gt 0) {
            Write-Host ''
            Write-Host ("  ... and {0} more finding(s). See the full reports." -f $remaining) -ForegroundColor DarkGray
        }
    }

    Write-Host ''
    Write-Host '  Reports written to:' -ForegroundColor White
    Write-Host ("    {0}" -f $OutputDirectory) -ForegroundColor Green
    Write-Host ''
}

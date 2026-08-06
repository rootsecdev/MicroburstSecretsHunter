function New-MBHtmlReport {
    <#
    .SYNOPSIS
        Writes a self-contained HTML report of findings (no external assets).
    #>
    [CmdletBinding()]
    param(
        [object[]]$Findings,
        [object]$ScanInfo,
        [Parameter(Mandatory)][string]$OutputPath
    )

    function ConvertTo-HtmlText([string]$s) {
        if ($null -eq $s) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($s)
    }

    $sevOrder = 'Critical','High','Medium','Low','Info'
    $counts = @{}
    foreach ($sev in $sevOrder) { $counts[$sev] = @($Findings | Where-Object Severity -eq $sev).Count }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>MicroBurst Secrets Hunter Report</title>')
    [void]$sb.AppendLine(@'
<style>
:root{--crit:#d1242f;--high:#a4279b;--med:#bf8700;--low:#0969da;--info:#6e7781;--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#8b949e;--border:#30363d}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}
header{padding:24px 28px;border-bottom:1px solid var(--border);background:var(--panel)}
header h1{margin:0 0 4px;font-size:20px}
header .meta{color:var(--muted);font-size:13px}
.wrap{padding:24px 28px;max-width:1400px;margin:0 auto}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.card{flex:1 1 120px;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.card .n{font-size:26px;font-weight:700}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.crit .n{color:var(--crit)} .card.high .n{color:var(--high)} .card.med .n{color:var(--med)}
.card.low .n{color:var(--low)} .card.info .n{color:var(--info)}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;align-items:center}
.controls input{background:var(--panel);border:1px solid var(--border);color:var(--text);padding:7px 10px;border-radius:6px;min-width:240px}
.btn{background:var(--panel);border:1px solid var(--border);color:var(--text);padding:6px 11px;border-radius:6px;cursor:pointer;font-size:13px}
.btn.active{border-color:#58a6ff;color:#58a6ff}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{background:#1c2128;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);position:sticky;top:0}
tr:last-child td{border-bottom:none}
td.ctx{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:#c9d1d9;word-break:break-all;max-width:520px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.b-Critical{background:var(--crit)} .b-High{background:var(--high)} .b-Medium{background:var(--med)}
.b-Low{background:var(--low)} .b-Info{background:var(--info)}
.path{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#7ee787;word-break:break-all}
.muted{color:var(--muted)}
footer{padding:16px 28px;color:var(--muted);font-size:12px;border-top:1px solid var(--border)}
.empty{padding:40px;text-align:center;color:#7ee787;font-size:16px}
.warn{margin:0 0 20px;padding:12px 16px;border-radius:8px;background:#3d2b00;border:1px solid #bf8700;color:#ffd866;font-weight:600}
</style>
'@)
    [void]$sb.AppendLine('</head><body>')

    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine('<h1>MicroBurst Secrets Hunter &mdash; Findings Report</h1>')
    $metaLine = '<div class="meta">Scan root: <code>{0}</code><br>Scanned {1} &middot; {2} of {3} files in {4}s &middot; entropy heuristic: {5}</div>' -f `
        (ConvertTo-HtmlText $ScanInfo.ScanRoot),
        (ConvertTo-HtmlText ($ScanInfo.ScannedAt.ToString('yyyy-MM-dd HH:mm:ss'))),
        $ScanInfo.FilesScanned, $ScanInfo.FilesTotal, $ScanInfo.DurationSec,
        ($(if($ScanInfo.EntropyEnabled){'on'}else{'off'}))
    [void]$sb.AppendLine($metaLine)
    [void]$sb.AppendLine('</header><div class="wrap">')

    # An unscanned file is a blind spot in the report; say so on the report
    # itself rather than only in the console the analyst has since closed.
    $skipped = [int]$ScanInfo.FilesSkippedSize + [int]$ScanInfo.FilesUnreadable
    if ($skipped -gt 0) {
        $parts = @()
        if ($ScanInfo.FilesSkippedSize -gt 0) { $parts += ('{0} over the size limit' -f $ScanInfo.FilesSkippedSize) }
        if ($ScanInfo.FilesUnreadable  -gt 0) { $parts += ('{0} unreadable' -f $ScanInfo.FilesUnreadable) }
        [void]$sb.AppendLine(('<div class="warn">&#9888; {0} file(s) were NOT scanned ({1}) and are not represented below.</div>' -f `
            $skipped, (ConvertTo-HtmlText ($parts -join ', '))))
    }

    if ($ScanInfo.Unredacted) {
        [void]$sb.AppendLine('<div class="warn">&#9888; This report contains UNREDACTED secret values (-ShowSecrets). Treat it as live credential material &mdash; store securely and delete when triage is complete.</div>')
    }

    # Cards
    [void]$sb.AppendLine('<div class="cards">')
    $cls = @{ Critical='crit'; High='high'; Medium='med'; Low='low'; Info='info' }
    foreach ($sev in $sevOrder) {
        $cardLine = '<div class="card {0}"><div class="n">{1}</div><div class="l">{2}</div></div>' -f `
            $cls[$sev], $counts[$sev], $sev
        [void]$sb.AppendLine($cardLine)
    }
    [void]$sb.AppendLine('<div class="card"><div class="n">{0}</div><div class="l">Total</div></div>' -f $Findings.Count)
    [void]$sb.AppendLine('</div>')

    if (-not $Findings -or $Findings.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No secrets detected.<br><span class="muted" style="font-size:13px">Absence of detections is not proof of safety &mdash; review the dump manually as well.</span></div>')
    } else {
        # Controls
        [void]$sb.AppendLine('<div class="controls">')
        [void]$sb.AppendLine('<input id="q" type="text" placeholder="Filter by file, rule, value..." oninput="flt()">')
        foreach ($sev in $sevOrder) {
            [void]$sb.AppendLine('<button class="btn active" data-sev="{0}" onclick="tog(this)">{0}</button>' -f $sev)
        }
        [void]$sb.AppendLine('</div>')

        # Table
        $valueHeader = if ($ScanInfo.Unredacted) { 'Value (RAW)' } else { 'Redacted value' }
        [void]$sb.AppendLine("<table id=`"t`"><thead><tr><th>Severity</th><th>Category</th><th>Rule</th><th>File</th><th>Line</th><th>$valueHeader</th><th>Context</th></tr></thead><tbody>")
        foreach ($f in $Findings) {
            $loc = if ($f.Line -gt 0) { $f.Line } else { '&mdash;' }
            $rowLine = '<tr data-sev="{0}"><td><span class="badge b-{0}">{0}</span></td><td>{1}</td><td>{2}<div class="muted">{3}</div></td><td class="path">{4}</td><td>{5}</td><td class="ctx">{6}</td><td class="ctx">{7}</td></tr>' -f `
                (ConvertTo-HtmlText $f.Severity),
                (ConvertTo-HtmlText $f.Category),
                (ConvertTo-HtmlText $f.RuleName),
                (ConvertTo-HtmlText $f.RuleId),
                (ConvertTo-HtmlText $f.File),
                $loc,
                (ConvertTo-HtmlText $f.Value),
                (ConvertTo-HtmlText $f.Context)
            [void]$sb.AppendLine($rowLine)
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    [void]$sb.AppendLine('</div>')
    $footerNote = if ($ScanInfo.Unredacted) { 'Secret values are shown UNREDACTED.' } else { 'Secret values are redacted.' }
    [void]$sb.AppendLine("<footer>Generated by MicroBurst Secrets Hunter. $footerNote Handle this report as sensitive.</footer>")

    [void]$sb.AppendLine(@'
<script>
var off={};
function tog(b){var s=b.dataset.sev;off[s]=!off[s];b.classList.toggle("active");flt();}
function flt(){
 var q=(document.getElementById("q").value||"").toLowerCase();
 document.querySelectorAll("#t tbody tr").forEach(function(r){
   var hideSev=off[r.dataset.sev];
   var match=r.textContent.toLowerCase().indexOf(q)>-1;
   r.style.display=(!hideSev&&match)?"":"none";
 });
}
</script>
'@)
    [void]$sb.AppendLine('</body></html>')

    $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding UTF8
}

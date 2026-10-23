# MicroBurst Secrets Hunter

A PowerShell scanner that combs through [MicroBurst](https://github.com/NetSPI/MicroBurst)
`Get-AzDomainInfo` output for plaintext passwords, keys, connection strings, and
other secrets that should never sit unencrypted in an Azure environment.

Built for **read-only audit workflows**: you collect a domain dump with MicroBurst
(Reader access is enough for `Get-AzDomainInfo`), then point this tool at the
output folder. It does **not** touch Azure itself — it only reads the files you
already exported. Secret values are **redacted** in every report, so the output
is safe to attach to findings.

---

## Quick start

```powershell
# Clone / copy this folder, then from a PowerShell prompt:
.\Scan-MicroBurst.ps1 -Path .\MicroBurst-2026 -Verbose
```

Or import the module and use the cmdlet directly:

```powershell
Import-Module .\MicroBurstSecretsHunter.psd1 -Force
Invoke-MBSecretScan -Path .\MicroBurst-2026
```

Reports are written to a timestamped folder (`MBSecretScan-<timestamp>`) in the
current directory unless you pass `-OutputDirectory`.

By default every value is **redacted** so the reports are safe to share. The
revealed characters are budgeted at a quarter of the value's length (capped at 4
leading + 2 trailing), and anything 8 characters or shorter is replaced with a
fixed-width mask — so a typical password shows as `********`, while an 88-char
storage key stays identifiable as `AAAA**********AA`. Context strings are
redacted *before* they are truncated, and every secret found on a line is
redacted out of every finding's context on that line, so no plaintext survives
in a report. When triaging false positives it's often faster to see the full value —
pass **`-ShowSecrets`** to emit unredacted values everywhere (console, CSV,
HTML, JSON, SARIF). The console and HTML then carry a clear warning banner, and the reports
must be treated as live credential material:

```powershell
Invoke-MBSecretScan -Path .\dump -ShowSecrets        # raw values, for local triage
```

Works on **PowerShell 7+** (Windows, Linux, macOS).

---

## What you get

Every run produces:

| Output | Description |
| --- | --- |
| **Console summary** | Color-coded counts by severity/category plus the top Critical/High findings. |
| **`findings.csv`** | One row per finding (severity, rule, file, line, redacted value, context) for triage in Excel. Fields carrying scanned content are escaped against spreadsheet formula injection. |
| **`report.html`** | Self-contained HTML report (no external assets, locked down by a Content-Security-Policy) with severity cards, live text filter, and severity toggles — shareable with the client. |
| **`findings.json`** | Scan metadata plus every finding, for scripting and tooling (`-NoJson` to skip). |
| **`findings.sarif`** | Optional SARIF 2.1.0 log for code-scanning tools (`-Sarif`). |

Each output folder also gets a small `.mbsecretscan-output` marker file so a
later scan whose root contains it skips it (see *Coverage limits*).

The cmdlet also emits finding objects to the pipeline, so you can post-process:

```powershell
$f = Invoke-MBSecretScan -Path .\dump -Quiet
$f | Where-Object Severity -eq 'Critical' | Format-Table File,Line,RuleName
```

---

## What it detects

| Rule | Severity | Example source in a dump |
| --- | --- | --- |
| SQL/DB connection string with embedded password | Critical | App Service settings, `web.config` exports |
| Azure Storage account connection string / 88-char key | Critical | App settings, Storage exports |
| Service Bus / Event Hub `SharedAccessKey` | Critical | Messaging resource configs |
| Cosmos DB account key | Critical | App settings |
| PEM private key block | Critical | Key Vault / certificate exports |
| Azure Function key (`?code=` in a Function / Logic App URL, `x-functions-key`) | High | Logic App definitions, app settings |
| ARM parameter value (`"adminPassword": { "value": "..." }`, including pretty-printed across lines) | High | ARM templates / parameter files |
| Azure Redis Cache password | High | Cache connection strings |
| Azure AD client secret (post-2021 `…Q~…` format) | High | ARM templates, app settings |
| SAS token / `sig=` parameter | High | Storage SAS URLs |
| JWT / bearer token | High | Cached tokens, configs |
| Certificate / key file present (`.pfx`, `.p12`, `.pem`, `.key`, `.jks`, `.ppk`, …) | High | Anywhere in the dump |
| Certificate file present (`.cer`, `.crt`, `.der` — usually public) | Low | Anywhere in the dump |
| Generic `password` / `pwd` assignment, including compound names (`administratorLoginPassword`, `userPWD`) | High | Automation variables, app settings, ARM params, publish profiles |
| Generic `secret` / `client_secret` assignment, including compound names (`servicePrincipalSecret`) | High | App settings, templates |
| AWS access key / GitHub / Slack tokens | High/Med | Foreign creds stored in Azure apps |
| Generic `api_key` / `access_key` / `connectionstring` | Medium | App settings |
| High-entropy string (heuristic) | Low | Backstop for unknown key formats — **opt-in** via `-IncludeEntropy` |

The generic keyword rules match the keyword at the *end* of a compound name
(`sqlAdminPassword`, `servicePrincipalSecret`, `storageAccountKey`), so
metadata fields that merely start with one (`passwordLastSet`, `secretName`)
stay quiet. A generic value stops before whitespace followed by another
`key=`/`key:`, so `password=abc apikey=xyz` yields two clean findings, while a
passphrase containing spaces is still captured whole.

**One finding per secret.** When several rules match the same value on the
same line (a storage connection string *and* the bare 88-char key; a SQL
connection string *and* the generic password rule), only the highest-severity
match is kept. On a tie, a format-specific rule (`AZ_AAD_CLIENT_SECRET`) wins
over a keyword-driven one (`GENERIC_*`, `ARM_PARAM_*`, `CSV_*`).

The full, editable rule set lives in **`Private/Get-MBSignature.ps1`**. Each rule
is a `[PSCustomObject]` with these fields:

| Field | Required | Purpose |
| --- | --- | --- |
| `Id`, `Name`, `Category`, `Severity` | yes | Identity and how the finding is reported and sorted. |
| `Pattern` | yes | The regex. Compiled once per scan. |
| `ValueGroup` | yes | Which capture group holds the secret (`0` = whole match). Drives redaction. |
| `MultiLine` | no | Evaluate against whole-file text instead of line by line (PEM blocks, pretty-printed ARM parameters). Every match is reported, not just the first, on the line where `ValueGroup` starts. |
| `CaseSensitive` | no | Opt out of the default `IgnoreCase` compilation. Set this for formats defined case-sensitively (`AKIA`, `ghp_`, `eyJ`, `Q~`) — without it, arbitrary-case lookalikes match. |
| `Redact` | no | Set `$false` when the captured value is a label rather than a secret (a PEM header line, a certificate file name) so it appears verbatim instead of masked into unreadability. Defaults to redacting. |

### Structured CSV column-pairing

`Get-AzDomainInfo` exports automation-account variables and app settings as
`Name,Value[,Encrypted]` rows. The secret lives in the **Value** column while
the keyword that identifies it (e.g. `ServiceAccountPwd`, `dbConnectionString`)
lives in the **Name** column — so a plain regex never sees them on the same
"line" and the keyword is buried inside a compound token with no word boundary.

For `.csv` / `.tsv` files the scanner additionally does **structured column
pairing** (`Private/Get-MBCsvFinding.ps1`):

- **Name/Value mode** — classifies each row's *Name* cell; if it's sensitive
  and the *Value* cell holds real data, it's reported. Rows marked
  `Encrypted=True` are skipped (the value is not plaintext).
- **Sensitive-column mode** — if a *column header* is itself sensitive
  (a `Password` or `StorageKey` column), every non-placeholder cell is reported.

Values that a high-confidence rule already covers (connection strings, storage
keys, SAS) are deferred to the raw-line pass for tighter redaction, and findings
are de-duplicated per value and line so the same secret is never reported twice. If a
file can't be parsed as a CSV, the scanner falls back to the normal raw-line
scan automatically.

#### Value-side scan (`-ScanValues`)

The pairing above keys off the *name* of a setting. To also catch secrets
stored under a meaningless name (e.g. `Config1 = P@ssw0rd2026!`), pass
**`-ScanValues`**. It inspects the *content* of value cells with two
conservative, **Low-severity** heuristics:

- **Password-like** — 8–64 chars, no whitespace, contains a strong special
  character (`!@#$%^&*` …) plus letters and another class. Identifier-style
  values like `Standard_D2s_v3` (whose only symbols are `_ - .`) are ignored.
- **High-entropy** — ≥ 16 chars, mixed letters+digits, Shannon entropy ≥
  `-MinEntropy`. Paths / URLs / resource IDs (anything containing `/` or `\`)
  are skipped to avoid flagging resource IDs.

In `Name/Value` tables it scans the Value column; in free-form tables it scans
every cell. This trades higher recall for more false positives, so it's **off
by default** — turn it on for a deeper sweep, then triage the Low findings.

---

## False-positive handling

Azure dumps are full of long random-looking strings that are **not** secrets.
The scanner filters these out:

- **GUIDs** (subscription / tenant / resource / object IDs) are never flagged.
- **Placeholders & non-secret value shapes** — `********`, `null`,
  `<provide-at-deploy>`, `true/false`, repeated characters, template tokens
  (`${var}`, `%VAR%`), JSON objects/arrays (`{...}`, `[...]`, including
  multi-line), dates/timestamps, and serialized .NET type/collection names
  (e.g. a VM scale set `Secrets` column rendering as
  `System.Collections.Generic.List`1[...VaultSecretGroup]`) — are skipped.
  Note this is shape-based: a `Secrets` column holding an actual plaintext
  value is still flagged.
- **Benign password-metadata fields** — directory columns whose name contains
  a keyword but only describe password *policy/state*, never the secret itself
  (`PasswordProfile`, `PasswordPolicies`, `ForceChangePasswordNextSignIn`,
  `LastPasswordChangeDateTime`, `PasswordExpirationDateTime`, …). These are
  common in RBAC exports like `InheritedOwners.csv` / `InheritedContributors.csv`
  and are not flagged, while a column genuinely named `Password` still is.
  Key Vault access-policy permission columns (`PermissionsToSecretsStr`,
  `PermissionsToKeysStr`, …) — which hold permission verbs like
  `Get, List, Set, Delete` — are likewise ignored.
- **Code & template expressions** — when `password`/`secret`/etc. is a variable
  or property name pointing at an expression rather than a literal, the captured
  value is skipped: PowerShell cmdlet calls (`Get-RandomPassword 8`,
  `Get-AzKeyVaultSecret ...`), variable references including scoped ones
  (`$result`, `$kv.Secrets`, `$global:clientSecret`, `$env:KEY`),
  sub-expressions (`(-join $x)`), and ARM / Logic App references
  (`@{body(...)}`, `@body(...)`, `[parameters('...')]`). Common in automation
  runbooks and Logic App definitions.

  The ambiguous shapes here — `$var`, `(expr)`, `Verb-Noun` — are only dismissed
  in files that actually contain code (`.ps1`, `.json`, `.tf`, `.yaml`, …).
  A password is very often a valid variable reference (`$ummer2026`,
  `$ecretPass1`), so applying that filter to CSV value cells discarded real
  secrets. Unambiguous template markers (`@{`, `@body(`, `[parameters(`) are
  filtered everywhere.
- **Column-header adjacency** — the generic `keyword = value` rules only treat
  `:` and `=` as separators (not `,`), so a CSV header like `...,AdminPassword,Secrets,...`
  no longer captures the *next column name* as a password. Comma-separated
  `Name,Value` pairs are still covered by the structured CSV pairing.
- **Resource-ID paths** are split into short segments instead of being treated
  as one high-entropy token.
- **Case-sensitive credential formats** (AWS `AKIA…`, GitHub `ghp_…`, JWT
  `eyJ…`, Azure AD `…Q~…`) are matched case-sensitively, so arbitrary-case
  lookalikes such as `akiaijklmnopqrstuvwx` are not reported. Keyword rules
  (`password=`, `AccountKey=`) stay case-insensitive.
- The **entropy heuristic is off by default** — it produces noisy Low-severity
  findings, so you opt in with `-IncludeEntropy` for a deeper sweep. Even then it
  only fires on tokens that look like key material (mixed letters+digits or
  base64 markers), so camelCase identifiers like `networkSecurityGroups` are
  ignored. Raise the bar further with `-MinEntropy 4.5`.

---

## Key parameters

| Parameter | Default | Purpose |
| --- | --- | --- |
| `-Path` | *(required)* | Root folder of the MicroBurst output. |
| `-OutputDirectory` | timestamped folder | Where reports are written (never scanned). Cannot be the scan root itself; a folder nested inside it warns. |
| `-IncludeEntropy` | off | Opt in to the high-entropy heuristic pass (adds Low-severity findings). |
| `-MinEntropy` | `4.0` | Shannon entropy threshold (bits/char) for the heuristic. |
| `-ScanValues` | off | Also inspect CSV value-cell *content* for secrets under innocuous names (Low-severity, higher recall). |
| `-ShowSecrets` | off | Emit **unredacted** values in all output to speed up false-positive triage. Reports become live credential material. |
| `-MaxFileSizeMB` | `50` | Skip files larger than this. Skipped files are warned about and counted in the summary and HTML report. |
| `-IncludeExtension` | common text types | Override which file types are scanned (a leading dot is optional). |
| `-SuppressionFile` | none | JSON file of known false positives to drop (see below). |
| `-Sarif` | off | Also write `findings.sarif`. |
| `-NoCsv` / `-NoHtml` / `-NoJson` | off | Skip a report format. |
| `-Quiet` | off | Suppress the console summary (objects still returned). |

`Scan-MicroBurst.ps1` accepts all of the above plus two options for scripted
and CI use:

| Parameter | Purpose |
| --- | --- |
| `-FailOnSeverity <Critical\|High\|Medium\|Low\|Info>` | Exit with code `1` when any finding is at or above that severity (`0` otherwise). |
| `-PassThru` | Emit the finding objects (the wrapper otherwise only prints the summary). |

```powershell
.\Scan-MicroBurst.ps1 -Path .\dump -Quiet -Sarif -FailOnSeverity High
```

### Suppressing known false positives

When you re-scan the same client, pass `-SuppressionFile` with the false
positives you have already triaged. It's a JSON array; a finding is dropped when
it matches **every** field an entry sets:

```json
[
  { "RuleId": "CERT_FILE", "Reason": "public certs, reviewed" },
  { "File": "*/Runbooks/Build-*.ps1", "RuleId": "GENERIC_PASSWORD", "Reason": "test fixture" },
  { "File": "*appsettings.csv", "ValuePattern": "^dummy-", "Reason": "placeholder values" }
]
```

| Field | Matches |
| --- | --- |
| `RuleId`, `Category` | Exact value. |
| `File` | Wildcard against the path relative to the scan root, using `/` separators. |
| `Line` | Exact line number. |
| `ValuePattern` | Regex against the **unredacted** value. |
| `Reason` | Free text for your notes; not used for matching. |

An entry that sets none of the matching fields would hide every finding, so it
is rejected. The suppressed count is shown in the console summary, the HTML
report, and `findings.json` — suppressed findings are never silently lost.

---

## Project layout

```
MicroBurstSecretsHunter.psd1     Module manifest
MicroBurstSecretsHunter.psm1     Module loader
Scan-MicroBurst.ps1              Convenience wrapper script
Public/
  Invoke-MBSecretScan.ps1        Main cmdlet (file walk, matching, reporting)
Private/
  Get-MBSignature.ps1            Detection rule set (edit to extend)
  Get-MBCsvFinding.ps1           Structured CSV Name/Value column pairing
  MBHelpers.ps1                  Entropy, redaction, context rendering,
                                 CSV field escaping, line windowing,
                                 placeholder/GUID filters
  MBSuppression.ps1              Suppression file loading / matching
  Write-MBConsoleSummary.ps1     Console output
  New-MBHtmlReport.ps1           HTML report generator
  New-MBSarifReport.ps1          SARIF 2.1.0 writer
tests/
  MicroBurstSecretsHunter.Tests.ps1   Pester tests
  sample-dump/                   Example Get-AzDomainInfo-style fixture
```

Run the tests (Pester 5+) from the project folder:

```powershell
Invoke-Pester ./tests
```

To try it against the bundled sample:

```powershell
.\Scan-MicroBurst.ps1 -Path .\tests\sample-dump
```

---

## Coverage limits the tool tells you about

Anything the scanner could not read is a blind spot, and a silent blind spot
reads as "nothing found here". So the scanner is explicit about them:

- Files over `-MaxFileSizeMB` produce a `Write-Warning` naming them, a
  `NOT scanned` line in the console summary, and a banner on the HTML report.
- Unreadable files (locked, permission-denied) are counted the same way; run
  with `-Verbose` for the individual paths. A read error never aborts the scan.
- **Earlier scanner output is skipped.** Running twice from inside a dump
  folder with the default output location would otherwise re-scan the first
  run's `findings.csv` / `report.html` and report its findings again (and,
  after a `-ShowSecrets` run, re-read plaintext). Folders with the
  `.mbsecretscan-output` marker, and default-named `MBSecretScan-<timestamp>`
  report folders from older versions, are skipped with a warning. Pointing
  `-Path` directly at an old report folder still scans it.
- Long lines are **not** truncated. Minified single-line JSON is normal in
  Azure exports, and a 14 KB one-line ARM template will happily hide an
  `AdminPassword` past any fixed cut-off, so lines are scanned in overlapping
  8000-character windows instead. A match cut off at a window edge is dropped
  in favour of the overlapping window that holds it whole, and finding context
  is always taken from the full line, so a secret cut by a window edge cannot
  slip through redaction.

---

## Notes & caveats

- **Absence of detections is not proof of safety.** Treat this as a force
  multiplier for manual review, not a replacement for it.
- By default reports redact secret values but still reveal *where* secrets live,
  so handle them as sensitive engagement artifacts. With `-ShowSecrets` they
  contain the **full plaintext credentials** — store securely and delete after
  triage.
- The tool is read-only and makes no network calls.

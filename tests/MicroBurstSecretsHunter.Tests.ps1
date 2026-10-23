#Requires -Modules Pester
# Run from the repo root:  Invoke-Pester ./tests
#
# Every scan writes into $TestDrive and uses throwaway fixture values; none of
# the "secrets" below are real.

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repo 'MicroBurstSecretsHunter.psd1') -Force
    $script:SampleDump = Join-Path $PSScriptRoot 'sample-dump'

    # Writes $Files (relative path -> content) into a fresh folder and scans it.
    function Invoke-TestScan {
        param(
            [hashtable]$Files = @{},
            [hashtable]$ScanParams = @{},
            [string]$Name = ([guid]::NewGuid().ToString('N'))
        )
        $root = Join-Path $TestDrive $Name
        $null = New-Item -ItemType Directory -Path $root -Force
        foreach ($k in $Files.Keys) {
            $p = Join-Path $root $k
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $p) -Force
            [System.IO.File]::WriteAllText($p, $Files[$k])
        }
        $out = Join-Path $TestDrive "$Name-out"
        $script:LastOut = $out
        @(Invoke-MBSecretScan -Path $root -OutputDirectory $out -Quiet @ScanParams 3>$null)
    }
}

Describe 'Sample dump' {
    BeforeAll {
        $script:sample = @(Invoke-MBSecretScan -Path $SampleDump -OutputDirectory (Join-Path $TestDrive 'sample-out') -Quiet)
    }

    It 'reports the expected rule set' {
        $got = $sample | ForEach-Object { '{0}|{1}' -f $_.RuleId, (Split-Path -Leaf $_.File) } | Sort-Object
        $expected = @(
            'AZ_AAD_CLIENT_SECRET|deploy-template.json'
            'AZ_SAS_TOKEN|keys.txt'
            'AZ_STORAGE_CONNSTR|webapp-prod-appsettings.csv'
            'AZ_STORAGE_KEY|keys.txt'
            'CSV_PASSWORD|automation-variables.csv'
            'CSV_PASSWORD|webapp-prod-appsettings.csv'
            'CSV_SECRET|VirtualMachineScaleSets.csv'
            'GENERIC_PASSWORD|New-Creds.ps1'
            'GENERIC_SECRET|New-Creds.ps1'
            'KEY_MATERIAL_FILE|exported.pem'
            'PRIVATE_KEY_BLOCK|exported.pem'
            'SQL_CONNSTR_PWD|webapp-prod-appsettings.csv'
        ) | Sort-Object
        $got | Should -Be $expected
    }

    It 'stays quiet on the benign fixture files' {
        $sample | Where-Object { $_.File -match 'resourcelist|InheritedOwners|AccessPolicies|VMInventory|logicapp' } |
            Should -BeNullOrEmpty
    }
}

Describe 'Detection: compound key names' {
    It 'finds <Desc>' -ForEach @(
        @{ Desc = 'ARM administratorLoginPassword'; File = 'a.json'; Text = '{ "administratorLoginPassword": "Winter2026!Prod" }'; Rule = 'GENERIC_PASSWORD'; Value = 'Winter2026!Prod' }
        @{ Desc = 'sqlAdminPassword';               File = 'b.json'; Text = '"sqlAdminPassword": "Spring2026!Prod"';             Rule = 'GENERIC_PASSWORD'; Value = 'Spring2026!Prod' }
        @{ Desc = 'publish profile userPWD';        File = 'p.xml';  Text = '<publishProfile userName="$app" userPWD="QxR7mZ2pLk9sWv4tYb8nHc3d" />'; Rule = 'GENERIC_PASSWORD'; Value = 'QxR7mZ2pLk9sWv4tYb8nHc3d' }
        @{ Desc = 'servicePrincipalSecret';         File = 'c.json'; Text = '"servicePrincipalSecret": "Zz9yXx8wVv7uTt6sRr5q"';    Rule = 'GENERIC_SECRET';   Value = 'Zz9yXx8wVv7uTt6sRr5q' }
        @{ Desc = 'storageAccountKey';              File = 'd.txt';  Text = 'storageAccountKey=Kq83hdUe72jdLs0a';              Rule = 'GENERIC_APIKEY';   Value = 'Kq83hdUe72jdLs0a' }
    ) {
        $r = Invoke-TestScan -Files @{ $File = $Text } -ScanParams @{ ShowSecrets = $true }
        $r.RuleId | Should -Contain $Rule
        ($r | Where-Object RuleId -eq $Rule).Value | Should -Be $Value
    }

    It 'ignores metadata fields that merely contain a keyword' {
        $r = Invoke-TestScan -Files @{ 'm.json' = '{ "passwordLastSet": "2024-01-01T00:00:00Z", "secretName": "my-vault-secret" }' }
        $r | Should -BeNullOrEmpty
    }

    It 'stops a generic value at the next key=value on the line' {
        $r = Invoke-TestScan -Files @{ 'x.txt' = 'password=FirstPw0rd! apikey=ZYXWVUTSRQ0123456789' } -ScanParams @{ ShowSecrets = $true }
        ($r | Where-Object RuleId -eq 'GENERIC_PASSWORD').Value | Should -Be 'FirstPw0rd!'
        ($r | Where-Object RuleId -eq 'GENERIC_APIKEY').Value   | Should -Be 'ZYXWVUTSRQ0123456789'
    }

    It 'keeps spaces inside a passphrase' {
        $r = Invoke-TestScan -Files @{ 'x.txt' = 'passphrase=correct horse battery' } -ScanParams @{ ShowSecrets = $true }
        $r[0].Value | Should -Be 'correct horse battery'
    }
}

Describe 'Detection: Azure formats' {
    It 'captures an AAD client secret ending in a non-word character, once' {
        $r = Invoke-TestScan -Files @{ 'a.txt' = 'clientSecret="Abc8Q~xY7zQwErTyUiOpAsDfGhJkLmNbVcXz1-"' } -ScanParams @{ ShowSecrets = $true }
        $r.Count     | Should -Be 1
        $r[0].RuleId | Should -Be 'AZ_AAD_CLIENT_SECRET'
        $r[0].Value  | Should -Be 'Abc8Q~xY7zQwErTyUiOpAsDfGhJkLmNbVcXz1-'
    }

    It 'labels a Cosmos DB connection string as Cosmos, reported once' {
        $key = ('A' * 40) + ('b' * 46) + '=='
        $r = Invoke-TestScan -Files @{ 'c.txt' = "AccountEndpoint=https://x.documents.azure.com:443/;AccountKey=$key;" }
        $r.Count     | Should -Be 1
        $r[0].RuleId | Should -Be 'AZ_COSMOS_KEY'
    }

    It 'reports a storage connection string once, not also as a bare key' {
        $key = ('A' * 40) + ('b' * 46) + '=='
        $r = Invoke-TestScan -Files @{ 's.txt' = "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=$key;EndpointSuffix=core.windows.net" }
        $r.Count     | Should -Be 1
        $r[0].RuleId | Should -Be 'AZ_STORAGE_CONNSTR'
    }

    It 'collapses a SQL connection string and the generic password rule to the Critical finding' {
        $r = Invoke-TestScan -Files @{ 'q.txt' = 'Server=tcp:x.database.windows.net;Database=db;User ID=sa;Password=Sup3rS3cret!Pass;' }
        $r.Count       | Should -Be 1
        $r[0].RuleId   | Should -Be 'SQL_CONNSTR_PWD'
        $r[0].Severity | Should -Be 'Critical'
    }

    It 'finds an Azure Function key in a URL and in a header' {
        $r = Invoke-TestScan -Files @{
            'u.txt' = 'https://fn.azurewebsites.net/api/HttpTrigger?code=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3x=='
            'h.txt' = 'x-functions-key: aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
        }
        $r.RuleId | Should -Contain 'AZ_FUNCTION_KEY_URL'
        $r.RuleId | Should -Contain 'AZ_FUNCTION_KEY_HEADER'
    }

    It 'does not treat an OAuth code= on an arbitrary redirect as a function key' {
        Invoke-TestScan -Files @{ 'o.txt' = 'https://example.com/callback?code=aB3dE5fG7hI9jK1lM3nO5pQ7rS9t' } |
            Should -BeNullOrEmpty
    }

    It 'finds a pretty-printed ARM parameter value on the value line' {
        $json = "{`n  `"sqlAdministratorLoginPassword`": {`n    `"value`": `"Pretty!Printed2026`"`n  }`n}"
        $r = Invoke-TestScan -Files @{ 'p.json' = $json }
        $r.Count     | Should -Be 1
        $r[0].RuleId | Should -Be 'ARM_PARAM_PASSWORD'
        $r[0].Line   | Should -Be 3
        $r[0].Context | Should -Not -Match 'Pretty!Printed2026'
    }

    It 'ignores ARM expressions and Key Vault references' {
        $json = "{ `"storageAccountKey`": {`n `"value`": `"[listKeys(variables('sa'), '2019-06-01').keys[0].value]`" },`n" +
                "  `"vmPassword`": { `"reference`": { `"secretName`": `"vmpw`" } } }"
        Invoke-TestScan -Files @{ 'p.json' = $json } | Should -BeNullOrEmpty
    }

    It 'matches AWS keys case-sensitively' {
        Invoke-TestScan -Files @{ 'k.txt' = 'id akiaijklmnopqrstuvwx' } | Should -BeNullOrEmpty
        (Invoke-TestScan -Files @{ 'k.txt' = 'id AKIAIJKLMNOPQRSTUVWX' }).RuleId | Should -Be 'AWS_ACCESS_KEY_ID'
    }
}

Describe 'Long lines' {
    It 'reports a secret straddling a window boundary once, whole, without leaking it' {
        $secret = 'LEAKMEsecret0123456789abcdefghijklmnopqrstuvw'
        $pre  = ('x' * 7900) + ' "password":"ShortPw9!",'
        $line = $pre + ('y' * (7945 - $pre.Length)) + " `"apikey`":`"$secret`" "
        $r = Invoke-TestScan -Files @{ 'seg.json' = $line } -ScanParams @{ ShowSecrets = $true }
        @($r | Where-Object RuleId -eq 'GENERIC_APIKEY').Count | Should -Be 1
        ($r | Where-Object RuleId -eq 'GENERIC_APIKEY').Value  | Should -Be $secret

        $red = Invoke-TestScan -Files @{ 'seg.json' = $line }
        $red | ForEach-Object { $_.Context | Should -Not -Match 'LEAKMEsecret0' }
    }

    It 'finds a secret far past the first window' {
        $r = Invoke-TestScan -Files @{ 'big.json' = ('z' * 30000) + ' "password": "DeepInLine99!" ' }
        $r.RuleId | Should -Be 'GENERIC_PASSWORD'
    }
}

Describe 'Redaction' {
    It 'never writes the raw secret to any report by default' {
        $secret = 'Wint3r2026Spring!Unique'
        $null = Invoke-TestScan -Files @{
            'v.csv'  = "Name,Value`nAdminPassword,$secret`n"
            'r.json' = "{ `"adminPassword`": `"$secret`" }"
        } -ScanParams @{ Sarif = $true }
        foreach ($f in 'findings.csv', 'findings.json', 'findings.sarif', 'report.html') {
            Get-Content -Raw (Join-Path $LastOut $f) | Should -Not -Match ([regex]::Escape($secret))
        }
    }

    It 'masks short values with a fixed-width mask' {
        InModuleScope MicroBurstSecretsHunter { Protect-MBValue 'P@ssw0rd' } | Should -Be '********'
    }

    It 'returns to redacting after a -ShowSecrets run' {
        $null = Invoke-TestScan -Files @{ 'a.txt' = 'password=Abcdefgh123!' } -ScanParams @{ ShowSecrets = $true }
        InModuleScope MicroBurstSecretsHunter { Protect-MBValue 'Abcdefgh123!XYZ' } | Should -Not -Be 'Abcdefgh123!XYZ'
    }
}

Describe 'Reports' {
    It 'escapes spreadsheet formulas in CSV fields' {
        InModuleScope MicroBurstSecretsHunter { Protect-MBCsvField '=HYPERLINK("x")' } | Should -Be "'=HYPERLINK(`"x`")"
    }

    It 'writes a header-only CSV when there are no findings' {
        $null = Invoke-TestScan -Files @{ 'empty.txt' = 'nothing here' }
        $csv = Get-Content (Join-Path $LastOut 'findings.csv')
        $csv | Should -HaveCount 1
        $csv | Should -Match '"Severity","Category","RuleId"'
    }

    It 'writes valid SARIF 2.1.0' {
        $null = Invoke-TestScan -Files @{ 'a.txt' = 'password=Abcdefgh123!' } -ScanParams @{ Sarif = $true }
        $s = Get-Content -Raw (Join-Path $LastOut 'findings.sarif') | ConvertFrom-Json
        $s.version | Should -Be '2.1.0'
        $s.runs[0].results[0].ruleId | Should -Be 'GENERIC_PASSWORD'
        $s.runs[0].results[0].level  | Should -Be 'error'
        $s.runs[0].results[0].locations[0].physicalLocation.region.startLine | Should -Be 1
    }

    It 'rates public certificate files Low and private key containers High' {
        $r = Invoke-TestScan -Files @{ 'pub.cer' = 'x'; 'priv.pfx' = 'x' }
        ($r | Where-Object Value -eq 'pub.cer').Severity  | Should -Be 'Low'
        ($r | Where-Object Value -eq 'priv.pfx').Severity | Should -Be 'High'
    }
}

Describe 'Earlier scanner output inside the scan root' {
    It 'is skipped on a second run' {
        $root = Join-Path $TestDrive 'rerun'
        $null = New-Item -ItemType Directory -Path $root
        Set-Content -LiteralPath (Join-Path $root 'vars.csv') -Value "Name,Value`nAdminPassword,Sup3rSecretPw!"
        $first  = @(Invoke-MBSecretScan -Path $root -OutputDirectory (Join-Path $root 'run1') -Quiet -ShowSecrets 3>$null)
        $second = @(Invoke-MBSecretScan -Path $root -OutputDirectory (Join-Path $root 'run2') -Quiet 3>$null)
        $first.Count  | Should -Be 1
        $second.Count | Should -Be 1
        $second[0].File | Should -Be 'vars.csv'
    }

    It 'skips legacy default-named report folders without a marker' {
        $r = Invoke-TestScan -Files @{
            'MBSecretScan-20250101-120000/findings.csv' = "Severity,Context`nHigh,password=OldPlaintext99!"
        }
        $r | Should -BeNullOrEmpty
    }

    It 'still scans an old report folder passed directly as -Path' {
        $old = Join-Path $TestDrive 'oldreport'
        $null = New-Item -ItemType Directory -Path $old
        Set-Content -LiteralPath (Join-Path $old '.mbsecretscan-output') -Value 'marker'
        Set-Content -LiteralPath (Join-Path $old 'notes.txt') -Value 'password=StillHere123!'
        @(Invoke-MBSecretScan -Path $old -OutputDirectory (Join-Path $TestDrive 'oldreport-out') -Quiet).Count | Should -Be 1
    }
}

Describe 'Suppression file' {
    BeforeAll {
        $script:files = @{ 'a.txt' = 'password=Abcdefgh123!'; 'pub.cer' = 'x' }
    }

    It 'drops findings matching every field of an entry' {
        $sf = Join-Path $TestDrive 'supp.json'
        '[ { "RuleId": "CERT_FILE" }, { "File": "a.*", "ValuePattern": "^Abc" } ]' | Set-Content $sf
        Invoke-TestScan -Files $files -ScanParams @{ SuppressionFile = $sf } | Should -BeNullOrEmpty
        (Get-Content -Raw (Join-Path $LastOut 'findings.json') | ConvertFrom-Json).ScanInfo.Suppressed | Should -Be 2
    }

    It 'keeps findings that match only some fields' {
        $sf = Join-Path $TestDrive 'supp2.json'
        '[ { "File": "a.txt", "ValuePattern": "^Nope" } ]' | Set-Content $sf
        (Invoke-TestScan -Files $files -ScanParams @{ SuppressionFile = $sf }).RuleId | Should -Contain 'GENERIC_PASSWORD'
    }

    It 'rejects an entry with no matching field' {
        $sf = Join-Path $TestDrive 'supp3.json'
        '[ { "Reason": "oops" } ]' | Set-Content $sf
        { Invoke-TestScan -Files $files -ScanParams @{ SuppressionFile = $sf } } | Should -Throw '*would suppress every finding*'
    }
}

Describe 'Coverage reporting' {
    It 'counts an unreadable file instead of aborting the scan' -Skip:(-not ($IsLinux -or $IsMacOS) -or [Environment]::UserName -eq 'root') {
        $root = Join-Path $TestDrive 'unreadable'
        $null = New-Item -ItemType Directory -Path $root
        Set-Content -LiteralPath (Join-Path $root 'ok.txt') -Value 'password=Readable123!'
        $locked = Join-Path $root 'locked.txt'
        Set-Content -LiteralPath $locked -Value 'password=Hidden123!'
        chmod 000 $locked
        try {
            $r = @(Invoke-MBSecretScan -Path $root -OutputDirectory (Join-Path $TestDrive 'unreadable-out') -Quiet 3>$null)
            $r.Count | Should -Be 1
            (Get-Content -Raw (Join-Path $TestDrive 'unreadable-out/findings.json') | ConvertFrom-Json).ScanInfo.FilesUnreadable |
                Should -Be 1
        } finally { chmod 644 $locked }
    }
}

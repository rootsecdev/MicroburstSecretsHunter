function Get-MBSignature {
    <#
    .SYNOPSIS
        Returns the secret-detection signature set used by the scanner.
    .DESCRIPTION
        Each signature is a PSCustomObject describing one detection rule. The
        scanner compiles the Pattern into a [regex] and evaluates it line-by-line
        (or, for multi-line rules such as PEM blocks, against whole-file text).

        Severity guidance:
            Critical - directly usable credential material (private keys,
                       storage/account keys, full connection strings with embedded keys).
            High     - passwords, client secrets, SAS signatures, bearer tokens.
            Medium   - API keys, keyword=value pairs, cloud access keys.
            Low      - heuristic / high-entropy candidates needing human triage.

        ValueGroup names which capture group holds the sensitive value (for
        redaction). 0 means the whole match. This applies to MultiLine rules
        too: their finding is reported on the line where that group starts.

        CaseSensitive suppresses the scanner's default IgnoreCase compilation.
        Set it on rules whose credential format is defined case-sensitively
        (AWS "AKIA", GitHub "ghp_", JWT "eyJ", Azure AD "Q~"); without it those
        patterns match arbitrary-case strings and produce false positives.

        Redact = $false marks a rule whose captured value is a non-secret
        label (a PEM header line, a file name) that should appear verbatim in
        the report instead of being masked into unreadability.
    #>
    [CmdletBinding()]
    param()

    @(
        # ----------------------------------------------------------------- #
        #  Azure connection strings & keys
        # ----------------------------------------------------------------- #
        # Cosmos precedes the storage rules: a Cosmos connection string also
        # contains 'AccountKey=' and would otherwise be labelled as Storage.
        [PSCustomObject]@{
            Id         = 'AZ_COSMOS_KEY'
            Name       = 'Cosmos DB account key'
            Category   = 'ConnectionString'
            Severity   = 'Critical'
            Pattern    = 'AccountEndpoint=https?://[^;]+;AccountKey=([A-Za-z0-9+/]{64,}={0,2})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'AZ_STORAGE_CONNSTR'
            Name       = 'Azure Storage account connection string'
            Category   = 'ConnectionString'
            Severity   = 'Critical'
            Pattern    = 'AccountKey\s*=\s*([A-Za-z0-9+/]{86,88}={0,2})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'AZ_STORAGE_KEY'
            Name       = 'Azure Storage account key (88-char base64)'
            Category   = 'Key'
            Severity   = 'Critical'
            Pattern    = '(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{86}==)(?![A-Za-z0-9+/])'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'AZ_SAS_TOKEN'
            Name       = 'Azure Shared Access Signature (SAS) token'
            Category   = 'Token'
            Severity   = 'High'
            Pattern    = '[?&](?:sig|sv)=[^&\s"'']+(?:&[a-z]{1,4}=[^&\s"'']*)*[?&]?sig=([A-Za-z0-9%]{20,})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'AZ_SAS_SIG'
            Name       = 'SAS signature parameter (sig=)'
            Category   = 'Token'
            Severity   = 'High'
            Pattern    = '\bsig=([A-Za-z0-9%]{27,})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'AZ_SERVICEBUS_KEY'
            Name       = 'Service Bus / Event Hub SharedAccessKey'
            Category   = 'ConnectionString'
            Severity   = 'Critical'
            Pattern    = 'SharedAccessKey\s*=\s*([A-Za-z0-9+/]{20,}={0,2})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'AZ_REDIS_KEY'
            Name       = 'Azure Redis Cache password'
            Category   = 'ConnectionString'
            Severity   = 'High'
            Pattern    = '\.redis\.cache\.windows\.net:\d+,password=([^,\r\n"'']+)'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'SQL_CONNSTR_PWD'
            Name       = 'SQL/DB connection string with embedded password'
            Category   = 'ConnectionString'
            Severity   = 'Critical'
            Pattern    = '(?:Server|Data Source|Initial Catalog|Database)\s*=[^;\r\n]+;(?:[^;\r\n]*;)*\s*(?:Password|Pwd)\s*=\s*([^;\r\n"'']+)'
            ValueGroup = 1
        }

        # ----------------------------------------------------------------- #
        #  Azure AD / OAuth credentials
        # ----------------------------------------------------------------- #
        [PSCustomObject]@{
            Id         = 'AZ_AAD_CLIENT_SECRET'
            Name       = 'Azure AD application client secret (post-2021 format)'
            Category   = 'Secret'
            Severity   = 'High'
            # Lookarounds rather than \b: the secret alphabet includes ~ . - which
            # are not word characters, so \b dropped or truncated secrets that
            # begin or end with one of them.
            Pattern    = '(?<![A-Za-z0-9_~.-])([A-Za-z0-9_~.-]{3}[0-9A-Za-z]Q~[A-Za-z0-9_~.-]{31,34})(?![A-Za-z0-9_~.-])'
            ValueGroup = 1
            CaseSensitive = $true
        }
        [PSCustomObject]@{
            Id         = 'JWT_TOKEN'
            Name       = 'JSON Web Token (JWT) / bearer token'
            Category   = 'Token'
            Severity   = 'High'
            Pattern    = '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
            ValueGroup = 0
            CaseSensitive = $true
        }

        # ----------------------------------------------------------------- #
        #  Private keys / certificates
        # ----------------------------------------------------------------- #
        [PSCustomObject]@{
            Id         = 'PRIVATE_KEY_BLOCK'
            Name       = 'PEM private key block'
            Category   = 'PrivateKey'
            Severity   = 'Critical'
            Pattern    = '-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----'
            ValueGroup = 0
            MultiLine  = $true
            Redact     = $false
        }

        # ----------------------------------------------------------------- #
        #  Foreign cloud / SaaS credentials (sometimes stored in Azure apps)
        # ----------------------------------------------------------------- #
        [PSCustomObject]@{
            Id         = 'AWS_ACCESS_KEY_ID'
            Name       = 'AWS access key ID'
            Category   = 'Key'
            Severity   = 'High'
            Pattern    = '\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b'
            ValueGroup = 1
            CaseSensitive = $true
        }
        [PSCustomObject]@{
            Id         = 'GITHUB_TOKEN'
            Name       = 'GitHub personal access token'
            Category   = 'Token'
            Severity   = 'High'
            Pattern    = '\b(gh[pousr]_[A-Za-z0-9]{36,255})\b'
            ValueGroup = 1
            CaseSensitive = $true
        }
        [PSCustomObject]@{
            Id         = 'SLACK_TOKEN'
            Name       = 'Slack token'
            Category   = 'Token'
            Severity   = 'Medium'
            Pattern    = '\b(xox[baprs]-[A-Za-z0-9-]{10,})\b'
            ValueGroup = 1
            CaseSensitive = $true
        }

        # ----------------------------------------------------------------- #
        #  Azure Functions keys
        # ----------------------------------------------------------------- #
        [PSCustomObject]@{
            Id         = 'AZ_FUNCTION_KEY_URL'
            Name       = 'Azure Function key in URL (code=)'
            Category   = 'Key'
            Severity   = 'High'
            # Function / Logic App callback URLs carry the key as ?code=...
            # Scoped to azurewebsites.net and /api/ routes so OAuth
            # authorization codes on arbitrary redirect URLs are not reported.
            Pattern    = '(?:\.azurewebsites\.net|/api/)[^\s"''?#]*\?(?:[^\s"''#]*&)?code=([A-Za-z0-9_%/+-]{20,}={0,2})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'AZ_FUNCTION_KEY_HEADER'
            Name       = 'Azure Function key header (x-functions-key)'
            Category   = 'Key'
            Severity   = 'High'
            Pattern    = '\bx-functions-key\b\s*["'']?\s*[:=]\s*["'']?([A-Za-z0-9_%/+-]{20,}={0,2})'
            ValueGroup = 1
        }

        # ----------------------------------------------------------------- #
        #  ARM template / parameter-file values
        # ----------------------------------------------------------------- #
        # ARM parameters nest the literal one level down:
        #   "adminPassword": { "value": "..." }
        # usually pretty-printed across several lines, which the line-based
        # keyword rules cannot see. MultiLine so \s spans the line breaks; the
        # finding is reported on the line holding the value.
        [PSCustomObject]@{
            Id         = 'ARM_PARAM_PASSWORD'
            Name       = 'ARM parameter password value'
            Category   = 'Password'
            Severity   = 'High'
            Pattern    = '(?i)"\w*?(?:password|passwd|pwd|passphrase)"\s*:\s*\{\s*"value"\s*:\s*"([^"\r\n]{4,200})"'
            ValueGroup = 1
            MultiLine  = $true
        }
        [PSCustomObject]@{
            Id         = 'ARM_PARAM_SECRET'
            Name       = 'ARM parameter secret / key value'
            Category   = 'Secret'
            Severity   = 'High'
            Pattern    = '(?i)"\w*?(?:secret|api[_-]?key|access[_-]?key|account[_-]?key|token)"\s*:\s*\{\s*"value"\s*:\s*"([^"\r\n]{6,400})"'
            ValueGroup = 1
            MultiLine  = $true
        }

        # ----------------------------------------------------------------- #
        #  Generic keyword = value (the workhorse for app settings,
        #  automation variables, ARM parameters, etc.)
        #
        #  Keywords match as the tail of a compound identifier (\w*? prefix):
        #  "administratorLoginPassword", "userPWD", "servicePrincipalSecret"
        #  and "storageAccountKey" are the real-world names, and a bare \b
        #  before the keyword missed all of them. The trailing \b still
        #  requires the keyword to END the name, so metadata fields such as
        #  "passwordLastSet" or "secretName" stay quiet.
        #
        #  The value stops before whitespace followed by another key= / key:,
        #  so "password=abc apikey=xyz" captures "abc" rather than the rest of
        #  the line, while a passphrase containing spaces is still captured.
        # ----------------------------------------------------------------- #
        [PSCustomObject]@{
            Id         = 'GENERIC_PASSWORD'
            Name       = 'Password assignment'
            Category   = 'Password'
            Severity   = 'High'
            Pattern    = '(?i)\b\w*?(?:password|passwd|pwd|passphrase)\b\s*["'']?\s*[:=]\s*["'']?((?:(?!\s+[\w.-]+\s*[:=])[^,;"''\r\n]){4,120})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'GENERIC_SECRET'
            Name       = 'Secret / client-secret assignment'
            Category   = 'Secret'
            Severity   = 'High'
            Pattern    = '(?i)\b\w*?(?:secret|secret[_-]?key)\b\s*["'']?\s*[:=]\s*["'']?((?:(?!\s+[\w.-]+\s*[:=])[^,;"''\r\n]){6,200})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'GENERIC_APIKEY'
            Name       = 'API key / access key assignment'
            Category   = 'Key'
            Severity   = 'Medium'
            Pattern    = '(?i)\b\w*?(?:api[_-]?key|apikey|access[_-]?key|account[_-]?key|primary[_-]?key|secondary[_-]?key|master[_-]?key|subscription[_-]?key|x-api-key)\b\s*["'']?\s*[:=]\s*["'']?((?:(?!\s+[\w.-]+\s*[:=])[^,;"''\r\n]){8,200})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'GENERIC_TOKEN'
            Name       = 'Token / bearer assignment'
            Category   = 'Token'
            Severity   = 'Medium'
            Pattern    = '(?i)\b\w*?(?:auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer|sas[_-]?token|connectionstring)\b\s*["'']?\s*[:=]\s*["'']?((?:(?!\s+[\w.-]+\s*[:=])[^,;"''\r\n]){8,400})'
            ValueGroup = 1
        }
    )
}

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
        redaction). 0 means the whole match.

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
            Id         = 'AZ_COSMOS_KEY'
            Name       = 'Cosmos DB account key'
            Category   = 'ConnectionString'
            Severity   = 'Critical'
            Pattern    = 'AccountEndpoint=https?://[^;]+;AccountKey=([A-Za-z0-9+/]{64,}={0,2})'
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
            Pattern    = '\b([A-Za-z0-9_~.-]{3}[0-9A-Za-z]Q~[A-Za-z0-9_~.-]{31,34})\b'
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
        #  Generic keyword = value (the workhorse for app settings,
        #  automation variables, ARM parameters, etc.)
        # ----------------------------------------------------------------- #
        [PSCustomObject]@{
            Id         = 'GENERIC_PASSWORD'
            Name       = 'Password assignment'
            Category   = 'Password'
            Severity   = 'High'
            Pattern    = '(?i)\b(?:admin)?(?:password|passwd|pwd)\b\s*["'']?\s*[:=]\s*["'']?([^,;"''\r\n]{4,120})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'GENERIC_SECRET'
            Name       = 'Secret / client-secret assignment'
            Category   = 'Secret'
            Severity   = 'High'
            Pattern    = '(?i)\b(?:client[_-]?secret|clientsecret|secret|secret[_-]?key)\b\s*["'']?\s*[:=]\s*["'']?([^,;"''\r\n]{6,200})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'GENERIC_APIKEY'
            Name       = 'API key / access key assignment'
            Category   = 'Key'
            Severity   = 'Medium'
            Pattern    = '(?i)\b(?:api[_-]?key|apikey|access[_-]?key|accountkey|primarykey|secondarykey|x-api-key)\b\s*["'']?\s*[:=]\s*["'']?([^,;"''\r\n]{8,200})'
            ValueGroup = 1
        }
        [PSCustomObject]@{
            Id         = 'GENERIC_TOKEN'
            Name       = 'Token / bearer assignment'
            Category   = 'Token'
            Severity   = 'Medium'
            Pattern    = '(?i)\b(?:auth[_-]?token|access[_-]?token|bearer|sas[_-]?token|connectionstring)\b\s*["'']?\s*[:=]\s*["'']?([^,;"''\r\n]{8,400})'
            ValueGroup = 1
        }
    )
}

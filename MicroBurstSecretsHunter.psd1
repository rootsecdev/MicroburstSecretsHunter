@{
    RootModule        = 'MicroBurstSecretsHunter.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'b8f3c2a1-4d6e-4f10-9a72-7c5e1d2b3a40'
    Author            = 'TrustedSec'
    Description       = 'Scans MicroBurst (Get-AzDomainInfo) output for plaintext passwords, keys, connection strings and other secrets. Read-only, audit-oriented.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-MBSecretScan')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Azure','Security','Audit','MicroBurst','Secrets','Pentest')
        }
    }
}

# MicroBurstSecretsHunter module loader.
# Dot-sources Private helpers then Public cmdlets, and exports the public surface.

$ErrorActionPreference = 'Stop'

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try { . $file.FullName }
    catch { throw "Failed to import $($file.FullName): $_" }
}

Export-ModuleMember -Function $public.BaseName

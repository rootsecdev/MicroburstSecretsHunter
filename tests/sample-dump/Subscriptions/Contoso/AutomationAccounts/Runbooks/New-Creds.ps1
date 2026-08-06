$length = 12
$password = Get-RandomPassword 8
$password = Get-RandomPassword $length $upper $lower $numeric
$password = (-join $result)
$password = Get-AzKeyVaultSecret -VaultName MyVault -Name AdminCred
$password = "P@ssw0rdReal123!"
$client_secret = $global:clientSecret
$client_secret = "aR3alLiteralClientSecretValue!"

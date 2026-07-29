param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_smartcard_expire_passwords'
        Levels = [int[]]@(4)
        Title = 'Comptes utilisateurs de carte à puce sans expiration de mot de passe'
    }
}

$smartCardPolicy = @($roots | Where-Object {
    $_.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' -notin @('1','TRUE','True','true')
} | Select-Object dn, 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts')
$results.Add((New-ControlResult 'vuln_smartcard_expire_passwords' @(4) 'Comptes utilisateurs de carte à puce sans expiration de mot de passe' `
    $(if ($smartCardPolicy.Count) { 'Failed' } else { 'Passed' }) $smartCardPolicy `
    'Activer msDS-ExpirePasswordsOnSmartCardOnlyAccounts sur chaque domaine.' "$prefix\root.tsv"))

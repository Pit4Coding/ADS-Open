param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_trusts_accounts'
        Levels = [int[]]@(2)
        Title = 'Comptes de trust dont le mot de passe est inchangé depuis plus d''un an'
    }
}

$trustAccounts = @($users | Where-Object {
    -not (Test-UacFlag $_ 2) -and (Test-UacFlag $_ 2048) -and
    (Convert-OradadDate $_.pwdLastSet) -lt $now.AddYears(-1)
} | Select-Object dn,sAMAccountName,pwdLastSet)
Add-RemainingControl 'vuln_trusts_accounts' @(2) `
    "Mot de passe ancien de compte d'approbation" $trustAccounts `
    "Réinitialiser les secrets des comptes d'approbation." "$prefix\user.tsv"

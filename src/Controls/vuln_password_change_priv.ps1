param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_priv'
        Levels = [int[]]@(1)
        Title = 'Comptes privilégiés dont le mot de passe est inchangé depuis plus de 3 ans'
    }
}

$oldPrivPassword = @($privilegedAccounts | Where-Object {
    (Convert-OradadDate $_.pwdLastSet) -lt $now.AddYears(-3)
} | Select-Object dn, sAMAccountName, pwdLastSet)
$results.Add((New-ControlResult 'vuln_password_change_priv' @(1) 'Comptes privilégiés dont le mot de passe est inchangé depuis plus de 3 ans' `
    $(if ($oldPrivPassword.Count) { 'Failed' } else { 'Passed' }) $oldPrivPassword `
    'Renouveler les secrets privilégiés concernés et mettre en place une rotation maîtrisée.' "$prefix\user.tsv; $prefix\group.tsv"))

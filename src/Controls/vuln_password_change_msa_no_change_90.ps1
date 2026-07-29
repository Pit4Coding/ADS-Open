param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_msa_no_change_90'
        Levels = [int[]]@(2)
        Title = 'Comptes de service managés dont le mot de passe de compte est inchangé depuis plus de 90 jours'
    }
}

$oldMsa = @($smsa + $gmsa | Where-Object {
    -not (Test-UacFlag $_ 2) -and (Convert-OradadDate $_.pwdLastSet) -lt $now.AddDays(-90)
} | Select-Object dn, sAMAccountName, pwdLastSet)
$results.Add((New-ControlResult 'vuln_password_change_msa_no_change_90' @(2) 'Comptes de service managés dont le mot de passe est inchangé depuis plus de 90 jours' `
    $(if ($oldMsa.Count) { 'Failed' } else { 'Passed' }) $oldMsa `
    'Diagnostiquer les comptes MSA/gMSA concernés et rétablir leur rotation automatique.' "$prefix\smsa.tsv; $prefix\gmsa.tsv"))

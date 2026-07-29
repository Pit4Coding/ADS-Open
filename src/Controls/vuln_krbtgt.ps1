param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_krbtgt'
        Levels = [int[]]@(2)
        Title = 'Mot de passe du compte krbtgt inchangé depuis plus d''un an'
    }
}

$krbtgt = @($users | Where-Object { $_.objectSid -match '-502$' -and (Convert-OradadDate $_.pwdLastSet) -lt $now.AddYears(-1) } |
    Select-Object dn, sAMAccountName, pwdLastSet)
$results.Add((New-ControlResult 'vuln_krbtgt' @(2) "Mot de passe du compte krbtgt inchangé depuis plus d'un an" `
    $(if ($krbtgt.Count) { 'Failed' } else { 'Passed' }) $krbtgt `
    'Effectuer une double rotation contrôlée du mot de passe krbtgt selon la procédure Microsoft.' "$prefix\user.tsv"))

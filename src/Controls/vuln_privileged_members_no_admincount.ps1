param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_privileged_members_no_admincount'
        Levels = [int[]]@(2)
        Title = 'Comptes membres de groupes privilégiés ayant un attribut adminCount vide ou valant 0'
    }
}

$privNoAdminCount = @($privilegedAccounts | Where-Object { $_.adminCount -ne '1' } |
    Select-Object dn, sAMAccountName, adminCount)
$results.Add((New-ControlResult 'vuln_privileged_members_no_admincount' @(2) 'Comptes membres de groupes privilégiés ayant un attribut adminCount vide ou valant 0' `
    $(if ($privNoAdminCount.Count) { 'Failed' } else { 'Passed' }) $privNoAdminCount `
    "Rechercher l'origine de la modification et restaurer la protection adminSDHolder." "$prefix\user.tsv; $prefix\group.tsv"))

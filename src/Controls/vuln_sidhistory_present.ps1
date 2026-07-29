param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_sidhistory_present'
        Levels = [int[]]@(3)
        Title = 'Comptes ou groupes ayant un historique de SID'
    }
}

$sidHistory = @($users + $groups | Where-Object { $_.sIDHistory } |
    Select-Object dn, sAMAccountName, sIDHistory)
$results.Add((New-ControlResult 'vuln_sidhistory_present' @(3) 'Comptes ou groupes ayant un historique de SID' `
    $(if ($sidHistory.Count) { 'Failed' } else { 'Passed' }) $sidHistory `
    "Qualifier chaque SIDHistory et le supprimer après la période de migration." "$prefix\user.tsv; $prefix\group.tsv"))

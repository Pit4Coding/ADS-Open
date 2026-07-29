param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_inactive_dc'
        Levels = [int[]]@(1)
        Title = 'Contrôleurs de domaines inactifs'
    }
}

$inactiveDc = @($computers | Where-Object {
    $_.primaryGroupID -in @('516','521') -and
    (Convert-OradadDate $_.lastLogonTimestamp) -lt $now.AddDays(-45)
} | Select-Object dn, sAMAccountName, lastLogonTimestamp)
$results.Add((New-ControlResult 'vuln_password_change_inactive_dc' @(1) 'Contrôleurs de domaines inactifs' `
    $(if ($inactiveDc.Count) { 'Failed' } else { 'Passed' }) $inactiveDc `
    "Qualifier puis retirer proprement les contrôleurs qui ne se sont pas authentifiés depuis 45 jours." "$prefix\computer.tsv"))

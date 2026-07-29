param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_inactive_servers'
        Levels = [int[]]@(3)
        Title = 'Serveurs inactifs'
    }
}

$inactiveServers = @($servers | Where-Object {
    (Convert-OradadDate $_.lastLogonTimestamp) -lt $now.AddDays(-90)
} | Select-Object dn, sAMAccountName, lastLogonTimestamp, operatingSystem)
$results.Add((New-ControlResult 'vuln_password_change_inactive_servers' @(3) 'Serveurs inactifs' `
    $(if ($inactiveServers.Count) { 'Failed' } else { 'Passed' }) $inactiveServers `
    'Qualifier, désactiver puis supprimer les comptes de serveurs obsolètes.' "$prefix\computer.tsv"))

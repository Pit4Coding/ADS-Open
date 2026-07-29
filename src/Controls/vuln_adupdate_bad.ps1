param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_adupdate_bad'
        Levels = [int[]]@(2)
        Title = 'Mauvaises versions de l''Active Directory'
    }
}

$adUpdate=@($allObjects | Where-Object dn -like 'CN=ActiveDirectoryUpdate,CN=DomainUpdates,*' |
    Where-Object { (Get-Integer $_.revision) -le 15 } | Select-Object dn,revision)
Add-RemainingControl 'vuln_adupdate_bad' @(2) `
    'Version dangereuse de la mise à jour du domaine Active Directory' $adUpdate `
    'Appliquer les mises à jour de domaine postérieures à la révision 15.' "$prefix\top.tsv"

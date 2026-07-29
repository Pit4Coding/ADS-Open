param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_privileged_members'
        Levels = [int[]]@(1,2)
        Title = 'Nombre important de membres des groupes privilégiés'
    }
}

$domainCount = [math]::Max(1,@($crossRefs | Where-Object dnsRoot).Count)
$privThreshold = [math]::Max(50,3*$domainCount)
$privCountFinding = if ($privilegedAccountsForCount.Count -gt $privThreshold) {
    @([pscustomobject]@{Count=$privilegedAccountsForCount.Count;Threshold=$privThreshold})
} else { @() }
Add-RemainingControl 'vuln_privileged_members' @(1,2) `
    'Nombre excessif de comptes privilégiés' $privCountFinding `
    'Réduire le nombre de comptes membres des groupes privilégiés.' `
    "$prefix\group.tsv; $prefix\user.tsv"

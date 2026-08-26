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
$privCountFinding = @(if ($privilegedAccountsForCount.Count -gt $privThreshold) {
    @([pscustomobject]@{Level=1;Count=$privilegedAccountsForCount.Count;Threshold=$privThreshold;Reason='Seuil quantitatif ANSSI dépassé'})
} else { @() })
$findings = @($privCountFinding) + @($privilegedServiceMemberships)
$failedLevels = @()
if ($privCountFinding.Count) { $failedLevels += @(1,2) }
if ($privilegedServiceMemberships.Count) { $failedLevels += 1 }
$failedLevels = @($failedLevels | Sort-Object -Unique)
$results.Add((New-ControlResult 'vuln_privileged_members' @(1,2) `
    'Membres non conformes des groupes privilégiés' `
    $(if ($findings.Count) { 'Failed' } else { 'Passed' }) $findings `
    'Retirer tout compte de service d''Administrators et de Domain Admins, et réduire le nombre de comptes privilégiés.' `
    "$prefix\group.tsv; $prefix\user.tsv; $prefix\smsa.tsv; $prefix\gmsa.tsv" `
    'Implemented' $failedLevels))
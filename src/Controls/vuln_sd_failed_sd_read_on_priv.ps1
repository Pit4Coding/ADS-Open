param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_sd_failed_sd_read_on_priv'; Levels=[int[]]@(3); Title='Informations critiques manquantes sur des comptes privilégiés' }
}
$failedPrivilegedSd = [System.Collections.Generic.List[object]]::new()
foreach ($dn in $privilegedAccountDns) {
    $key = $dn.ToLowerInvariant()
    if (-not $objectByDn.ContainsKey($key) -or -not $objectByDn[$key].nTSecurityDescriptor) {
        $failedPrivilegedSd.Add([pscustomobject]@{ Dn=$dn; Reason='Descripteur absent' })
    }
}
foreach ($error in $acl.ParseErrors | Where-Object Dn -in $privilegedAccountDns) {
    $failedPrivilegedSd.Add([pscustomobject]@{ Dn=$error.Dn; Reason=$error.Error })
}
$results.Add((New-ControlResult 'vuln_sd_failed_sd_read_on_priv' @(3) `
    'Comptes privilégiés pour lesquels des informations critiques sont manquantes' `
    $(if ($failedPrivilegedSd.Count) { 'Failed' } else { 'Passed' }) @($failedPrivilegedSd) `
    'Rétablir la lecture complète des descripteurs de sécurité des comptes privilégiés.' `
    'nTSecurityDescriptor (membres privilégiés)' 'Implemented'))

param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_cluster_no_change_3years'
        Levels = [int[]]@(2)
        Title = 'Comptes utilisés dans un cluster de basculement Windows Server dont le mot de passe est inchangé depuis plus de 3 ans'
    }
}

$clusterOld = @($users+$computers | Where-Object {
    $_.servicePrincipalName -match '(?i)MSCluster' -and
    (Convert-OradadDate $_.pwdLastSet) -lt $now.AddYears(-3)
} | Select-Object dn,sAMAccountName,pwdLastSet,servicePrincipalName)
Add-RemainingControl 'vuln_password_change_cluster_no_change_3years' @(2) `
    'Secret de compte de cluster inchangé depuis plus de trois ans' $clusterOld `
    'Renouveler les secrets des comptes de cluster.' "$prefix\user.tsv; $prefix\computer.tsv"

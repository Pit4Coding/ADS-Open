param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_rodc_orphan_krbtgt'; Levels=[int[]]@(3); Title='Comptes krbtgt de RODC orphelins' }
}
Add-RemainingControl 'vuln_rodc_orphan_krbtgt' @(3) `
        'Compte krbtgt de RODC orphelin' $orphanKrb `
        'Supprimer les comptes krbtgt de RODC sans contrôleur associé.' "$prefix\user.tsv; $prefix\computer.tsv"
param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_trusts_forest_sidhistory'; Levels=[int[]]@(1); Title='Relations d''approbation sortantes de type forêt avec sID History activé' }
}
Add-RemainingControl 'vuln_trusts_forest_sidhistory' @(1) `
        'Filtrage SID affaibli sur une approbation de forêt' $forestSidHistory `
        'Activer le filtrage SID strict sur les approbations de forêt.' "$prefix\trustedDomain.tsv"
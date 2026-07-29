param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_rodc_reveal'; Levels=[int[]]@(3); Title='Comptes ou groupes privilégiés présents dans les attributs de révélation des RODC' }
}
Add-RemainingControl 'vuln_rodc_reveal' @(3) `
        'Groupe privilégié autorisé dans RevealOnDemand' $revealBad `
        'Retirer les groupes privilégiés de RevealOnDemand.' "$prefix\computer.tsv"
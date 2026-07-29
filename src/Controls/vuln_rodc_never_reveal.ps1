param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_rodc_never_reveal'; Levels=[int[]]@(3); Title='Configuration dangereuse des contrôleurs de domaine en lecture seule (RODC) (neverReveal)' }
}
Add-RemainingControl 'vuln_rodc_never_reveal' @(3) `
        "Liste NeverReveal d'un RODC incomplète" $neverRevealBad `
        'Ajouter tous les groupes privilégiés par défaut à NeverReveal.' "$prefix\computer.tsv"
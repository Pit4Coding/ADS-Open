param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_rodc_denied_group'; Levels=[int[]]@(3); Title='Configuration dangereuse des groupes de réplication pour les contrôleurs de domaine en lecture seule (RODC) (denied)' }
}
Add-RemainingControl 'vuln_rodc_denied_group' @(3) `
        'Groupe Denied RODC Password Replication incomplet' $deniedBad `
        'Rétablir les membres privilégiés par défaut du groupe Denied RODC.' "$prefix\group.tsv"
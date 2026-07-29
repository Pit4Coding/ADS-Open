param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_rodc_allowed_group'; Levels=[int[]]@(3); Title='Configuration dangereuse des groupes de réplication pour les contrôleurs de domaine en lecture seule (RODC) (allow)' }
}
Add-RemainingControl 'vuln_rodc_allowed_group' @(3) `
        'Groupe Allowed RODC Password Replication non vide' $allowed571 `
        'Vider le groupe Allowed RODC Password Replication Group.' "$prefix\group.tsv"
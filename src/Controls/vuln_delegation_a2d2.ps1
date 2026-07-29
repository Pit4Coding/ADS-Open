param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_delegation_a2d2'; Levels=[int[]]@(1); Title='Délégation d''authentification contrainte vers un service privilégié' }
}
Add-RemainingControl 'vuln_delegation_a2d2' @(1) `
        'Délégation contrainte vers un service privilégié' $delegations `
        'Supprimer les délégations contraintes ciblant les services privilégiés.' `
        "$prefix\user.tsv; $prefix\computer.tsv"
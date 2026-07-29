param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_delegation_t2a4d'; Levels=[int[]]@(1); Title='Délégation d''authentification contrainte avec transition de protocole vers un service privilégié' }
}
Add-RemainingControl 'vuln_delegation_t2a4d' @(1) `
        'Transition de protocole vers un service privilégié' $protocolTransition `
        'Désactiver TRUSTED_TO_AUTH_FOR_DELEGATION vers les services privilégiés.' `
        "$prefix\user.tsv; $prefix\computer.tsv"
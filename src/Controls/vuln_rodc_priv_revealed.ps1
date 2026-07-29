param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_rodc_priv_revealed'; Levels=[int[]]@(2); Title='Comptes ou groupes privilégiés révélés par des RODC' }
}
Add-RemainingControl 'vuln_rodc_priv_revealed' @(2) `
        'Secrets privilégiés révélés à un RODC' $revealedPriv `
        'Purger les secrets privilégiés mis en cache et corriger la stratégie RODC.' "$prefix\computer.tsv"
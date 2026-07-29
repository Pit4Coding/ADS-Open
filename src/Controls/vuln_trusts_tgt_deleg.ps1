param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_trusts_tgt_deleg'; Levels=[int[]]@(3); Title='Relations d''approbation entrante avec délégation' }
}
Add-RemainingControl 'vuln_trusts_tgt_deleg' @(3) `
        'Délégation TGT autorisée sur une approbation' $tgtDeleg `
        "Désactiver la délégation Kerberos inter-forêts lorsqu'elle n'est pas indispensable." `
        "$prefix\trustedDomain.tsv"
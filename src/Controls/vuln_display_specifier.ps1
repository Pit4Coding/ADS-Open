param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_display_specifier'; Levels=[int[]]@(1); Title='Présence de Display Specifiers dangereux' }
}
Add-RemainingControl 'vuln_display_specifier' @(1) `
        'Script de Display Specifier hors SYSVOL' $displayBad `
        "Héberger les scripts d'administration dans SYSVOL et contrôler leurs ACL." `
        'configuration\displaySpecifier.tsv'
param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_owner'; Levels=[int[]]@(3); Title='Objets ayant un propriétaire inadapté' }
}
Add-AclControl 'vuln_owner' @(3) `
        'Objets ayant un propriétaire inadapté' $badOwners `
        'Attribuer la propriété des objets à un principal administratif attendu.'
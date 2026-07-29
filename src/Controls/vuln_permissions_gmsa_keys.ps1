param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_gmsa_keys'; Levels=[int[]]@(1,2); Title='Permissions dangereuses vers les objets de clés gMSA (chemins de contrôle)' }
}
Add-AclControl 'vuln_permissions_gmsa_keys' @(1,2) `
        'Permissions dangereuses vers les objets de clés gMSA (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -in $gmsaDns | Select-Object $relationFields) `
        'Restreindre les permissions permettant de modifier les comptes gMSA ou les principaux autorisés.'
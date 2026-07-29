param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_schema'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur les objets du schéma (chemins de contrôle)' }
}
Add-AclControl 'vuln_permissions_schema' @(1,2) `
        'Permissions dangereuses sur les objets du schéma (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -like "*,$schemaDn" | Select-Object $relationFields) `
        'Restreindre les modifications du schéma aux seuls administrateurs du schéma.'
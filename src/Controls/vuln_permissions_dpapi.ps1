param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_dpapi'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur les objets de clés DPAPI (chemins de contrôle)' }
}
Add-AclControl 'vuln_permissions_dpapi' @(1,2) `
        'Permissions dangereuses sur les objets de clés DPAPI (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -match '^CN=BCKUPKEY_.*?,CN=System,' |
            Select-Object $relationFields) `
        'Restreindre les permissions sur les objets de clés de sauvegarde DPAPI.'
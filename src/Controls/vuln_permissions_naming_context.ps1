param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_naming_context'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur la racine des naming contexts (chemins de contrôle)' }
}
Add-AclControl 'vuln_permissions_naming_context' @(1,2) `
        'Permissions dangereuses sur la racine des naming contexts (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -in @($domainDn,$configurationDn,$schemaDn) |
            Select-Object $relationFields) `
        'Retirer les permissions dangereuses sur les racines des partitions.'
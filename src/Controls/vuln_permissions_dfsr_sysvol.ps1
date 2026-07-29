param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_dfsr_sysvol'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur les objets des paramètres DFSR du SYSVOL (chemins de contrôle)' }
}
Add-AclControl 'vuln_permissions_dfsr_sysvol' @(1,2) `
        'Permissions dangereuses sur les objets des paramètres DFSR du SYSVOL (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -match 'CN=(Domain System Volume|SYSVOL Subscription),' |
            Select-Object $relationFields) `
        'Restaurer les permissions attendues sur la configuration DFSR du SYSVOL.'
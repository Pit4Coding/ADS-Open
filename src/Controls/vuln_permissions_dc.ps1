param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_dc'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur les objets contrôleurs de domaine (chemins de contrôle)' }
}
Add-AclControl 'vuln_permissions_dc' @(1,2) `
        'Permissions dangereuses sur les objets contrôleurs de domaine (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -in $dcDns | Select-Object $relationFields) `
        'Retirer les permissions permettant la prise de contrôle des comptes de contrôleurs de domaine.'
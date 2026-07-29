param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_adminsdholder'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur l''objet adminSDHolder' }
}
Add-AclControl 'vuln_permissions_adminsdholder' @(1,2) `
        "Permissions dangereuses sur l'objet adminSDHolder" `
        @($actionableAclRelations | Where-Object TargetDn -like 'CN=AdminSDHolder,*' | Select-Object $relationFields) `
        "Restaurer le descripteur de sécurité de référence d'adminSDHolder."
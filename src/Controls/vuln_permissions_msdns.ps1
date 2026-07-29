param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_permissions_msdns'; Levels=[int[]]@(1); Title='Permissions dangereuses sur les objets serveurs MicrosoftDNS (chemins de contrôle)' }
}
Add-AclControl 'vuln_permissions_msdns' @(1) `
        'Permissions dangereuses sur les objets serveurs MicrosoftDNS (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -like 'CN=MicrosoftDNS,*' | Select-Object $relationFields) `
        'Retirer les permissions de contrôle dangereuses sur les objets MicrosoftDNS.'
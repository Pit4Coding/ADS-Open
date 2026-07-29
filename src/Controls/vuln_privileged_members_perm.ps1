param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_privileged_members_perm'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur des membres de groupes privilégiés (chemins de contrôle)' }
}
Add-AclControl 'vuln_privileged_members_perm' @(1,2) `
        'Permissions dangereuses sur des membres de groupes privilégiés (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -in $privilegedAccountDns | Select-Object $relationFields) `
        'Protéger les comptes privilégiés au moins au niveau du modèle adminSDHolder.'
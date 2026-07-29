param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_permissions_gpo_priv'
        Levels = [int[]]@(1)
        Title = 'Permissions dangereuses sur les objets de GPO s''appliquant aux membres des groupes privilégiés (chemins de contrôle)'
    }
}

# GPO applicables aux comptes privilégiés : liens du domaine et de leurs OU parentes.
$applicableGpoGuids = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$links = @($roots | ForEach-Object gPLink)
foreach ($account in $privilegedAccounts) {
    foreach ($ou in $ous) {
        if ($account.dn.EndsWith(",$($ou.dn)", [System.StringComparison]::OrdinalIgnoreCase)) {
            $links += $ou.gPLink
        }
    }
}
foreach ($link in $links) {
    foreach ($match in [regex]::Matches([string]$link, '\{[0-9A-Fa-f-]{36}\}')) {
        [void]$applicableGpoGuids.Add($match.Value)
    }
}
$applicableGpoDns = @($gpos | Where-Object { $applicableGpoGuids.Contains($_.cn) } | ForEach-Object dn)
Add-AclControl 'vuln_permissions_gpo_priv' @(1) `
    "Permissions dangereuses sur les objets de GPO s'appliquant aux membres des groupes privilégiés (chemins de contrôle)" `
    @($actionableAclRelations | Where-Object TargetDn -in $applicableGpoDns | Select-Object $relationFields) `
    "Restreindre les permissions de modification des GPO qui s'appliquent aux comptes privilégiés."

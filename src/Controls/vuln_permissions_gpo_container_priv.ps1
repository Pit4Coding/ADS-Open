param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_permissions_gpo_container_priv'
        Levels = [int[]]@(2)
        Title = 'Permissions dangereuses sur des conteneurs d''objets privilégiés (chemins de contrôle)'
    }
}

$privilegedContainerDns = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($account in $privilegedAccounts) {
    $parent = $account.dn.Substring($account.dn.IndexOf(',') + 1)
    while ($parent -and $parent -ne $domainDn) {
        [void]$privilegedContainerDns.Add($parent)
        $comma = $parent.IndexOf(',')
        if ($comma -lt 0) { break }
        $parent = $parent.Substring($comma + 1)
    }
}
Add-AclControl 'vuln_permissions_gpo_container_priv' @(2) `
    "Permissions dangereuses sur des conteneurs d'objets privilégiés (chemins de contrôle)" `
    @($actionableAclRelations | Where-Object { $privilegedContainerDns.Contains($_.TargetDn) } |
        Select-Object $relationFields) `
    "Restreindre les permissions sur les conteneurs qui hébergent des objets privilégiés."

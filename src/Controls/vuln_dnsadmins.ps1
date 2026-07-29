param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_dnsadmins'; Levels=[int[]]@(1); Title='Permissions dangereuses sur le groupe DnsAdmins' }
}
Add-AclControl 'vuln_dnsadmins' @(1) `
        'Permissions dangereuses sur le groupe DnsAdmins' `
        $dnsAdminFindings `
        'Vider DnsAdmins et déléguer finement les opérations de gestion DNS.'
param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_dnszone_bad_prop'; Levels=[int[]]@(1,3); Title='Zones DNS mal configurées' }
}
Add-RemainingControl 'vuln_dnszone_bad_prop' @(1,3) `
        'Propriétés dangereuses de zones DNS' $dnsBad `
        'Interdire les mises à jour dynamiques non sécurisées et corriger les propriétés DNS.' `
        'domain/domaindns/forestdns dnsZone.tsv'
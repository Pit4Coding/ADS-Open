param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_trusts_domain_notfiltered'
        Levels = [int[]]@(1)
        Title = 'Relations d''approbation sortante de type domaine non filtré'
    }
}

$dangerousTrusts = @($trusts | Where-Object {
    $_.trustDirection -match 'OUTBOUND|BIDIRECTIONAL' -and $_.trustAttributes -notmatch 'QUARANTINED|FOREST_TRANSITIVE'
} | Select-Object dn, trustPartner, trustDirection, trustAttributes)
$results.Add((New-ControlResult 'vuln_trusts_domain_notfiltered' @(1) "Relations d'approbation sortante de type domaine non filtré" `
    $(if ($dangerousTrusts.Count) { 'Failed' } else { 'Passed' }) $dangerousTrusts `
    'Activer le filtrage des SID et qualifier les besoins de transitivité.' "$prefix\trustedDomain.tsv"))

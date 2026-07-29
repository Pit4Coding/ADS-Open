param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_sysvol_ntfrs'
        Levels = [int[]]@(2)
        Title = 'Utilisation de NTFRS pour la réplication du SYSVOL'
    }
}

$ntfrsFinding = @($ntfrs | Select-Object dn, fRSReplicaSetType)
$results.Add((New-ControlResult 'vuln_sysvol_ntfrs' @(2) 'Utilisation de NTFRS pour la réplication du SYSVOL' `
    $(if ($ntfrsFinding.Count) { 'Failed' } else { 'Passed' }) $ntfrsFinding `
    'Migrer la réplication SYSVOL de NTFRS vers DFSR.' "$prefix\nTFRSReplicaSet.tsv"))

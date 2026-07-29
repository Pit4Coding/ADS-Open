param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_primary_group_id_nochange'
        Levels = [int[]]@(3)
        Title = 'Comptes avec un PrimaryGroupID modifié'
    }
}

$primaryChanged = @($users + $computers | Where-Object {
    $allowed = if ($_.PSObject.Properties.Name -contains 'operatingSystem') {
        @('515','516','521')
    } else {
        @('513','514')
    }
    $_.primaryGroupID -and $_.primaryGroupID -notin $allowed
} | Select-Object dn, sAMAccountName, primaryGroupID)
$results.Add((New-ControlResult 'vuln_primary_group_id_nochange' @(3) 'Comptes avec un PrimaryGroupID modifié' `
    $(if ($primaryChanged.Count) { 'Failed' } else { 'Passed' }) $primaryChanged `
    'Restaurer le groupe principal attendu et contrôler les appartenances du compte.' "$prefix\user.tsv; $prefix\computer.tsv"))

param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_primary_group_id_1000'
        Levels = [int[]]@(1)
        Title = 'Comptes avec un PrimaryGroupID inférieur à 1000'
    }
}

$primaryLow = @($users + $computers | Where-Object {
    $v = 999
    [int]::TryParse([string]$_.primaryGroupID, [ref]$v) -and $v -lt 1000 -and $v -notin @(513, 514, 515, 516, 517, 521)
} | Select-Object dn, sAMAccountName, primaryGroupID)
$results.Add((New-ControlResult 'vuln_primary_group_id_1000' @(1) 'Comptes avec un PrimaryGroupID inférieur à 1000' `
    $(if ($primaryLow.Count) { 'Failed' } else { 'Passed' }) $primaryLow `
    'Restaurer un groupe principal standard et vérifier les appartenances privilégiées.' "$prefix\user.tsv; $prefix\computer.tsv"))

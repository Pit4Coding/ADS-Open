param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_dc_obsolete'
        Levels = [int[]]@(1)
        Title = 'DC/RODC ayant un système d''exploitation obsolète'
    }
}

$obsoleteDc = @($computers | Where-Object {
    $_.primaryGroupID -in @('516','521') -and $_.operatingSystem -match '2000|2003|2008|2012'
} | Select-Object dn, sAMAccountName, operatingSystem, operatingSystemVersion)
$results.Add((New-ControlResult 'vuln_dc_obsolete' @(1) "DC/RODC ayant un système d'exploitation obsolète" `
    $(if ($obsoleteDc.Count) { 'Failed' } else { 'Passed' }) $obsoleteDc `
    "Migrer les contrôleurs de domaine vers une version Windows Server maintenue." "$prefix\computer.tsv"))

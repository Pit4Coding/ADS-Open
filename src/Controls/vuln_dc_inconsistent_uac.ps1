param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_dc_inconsistent_uac'
        Levels = [int[]]@(1)
        Title = 'Contrôleurs de domaine incohérents'
    }
}

$inconsistentDc = @($computers | Where-Object {
    $isDcGroup = $_.primaryGroupID -in @('516','521')
    $isDcFlag = Test-UacFlag $_ 8192
    $isDcGroup -ne $isDcFlag
} | Select-Object dn, sAMAccountName, primaryGroupID, userAccountControl)
$results.Add((New-ControlResult 'vuln_dc_inconsistent_uac' @(1) 'Contrôleurs de domaine incohérents' `
    $(if ($inconsistentDc.Count) { 'Failed' } else { 'Passed' }) $inconsistentDc `
    'Rétablir la cohérence entre le type de compte, le groupe principal et les indicateurs UAC du contrôleur.' "$prefix\computer.tsv"))

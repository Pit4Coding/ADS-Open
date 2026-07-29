param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_functional_level'
        Levels = [int[]]@(1,3,4)
        Title = 'Niveaux fonctionnels de la forêt et des domaines insuffisants'
    }
}

$functionalFindings = [System.Collections.Generic.List[object]]::new()
foreach ($o in @($roots + $crossRefs | Where-Object { $_.'msDS-Behavior-Version' -ne '' })) {
    $v=Get-Integer $o.'msDS-Behavior-Version'
    $failedLevel = if ($v -lt 4) { 1 } elseif ($v -lt 6) { 3 } elseif ($v -lt 7) { 4 } else { 0 }
    if ($failedLevel) {
        $functionalFindings.Add([pscustomobject]@{
            Dn=$o.dn;Version=$v;Required=7;Level=$failedLevel
        })
    }
}
$functionalFailedLevels = @($functionalFindings | ForEach-Object Level | Sort-Object -Unique)
$results.Add((New-ControlResult 'vuln_functional_level' @(1,3,4) `
    'Niveaux fonctionnels obsolètes' `
    $(if ($functionalFindings.Count) {'Failed'} else {'Passed'}) @($functionalFindings) `
    'Élever les niveaux fonctionnels de forêt et de domaine à Windows Server 2016 ou supérieur.' `
    "$prefix\root.tsv; configuration\crossRef.tsv" 'Implemented' $functionalFailedLevels))

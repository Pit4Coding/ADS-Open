param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_group_loop'
        Levels = [int[]]@(4)
        Title = 'Présences de boucles d''imbrication de groupes'
    }
}

$groupLoops=[System.Collections.Generic.List[object]]::new()
function Visit-Group([string]$start,[string]$current,[string[]]$path) {
    if ($path -contains $current) {
        $groupLoops.Add([pscustomobject]@{Start=$start;Path=(($path+$current) -join ' -> ')})
        return
    }
    if (-not $groupByDn.ContainsKey($current.ToLowerInvariant())) { return }
    $members = @(Split-MultiValue $groupByDn[$current.ToLowerInvariant()].member)
    foreach ($m in $members) {
        if ($groupByDn.ContainsKey($m.ToLowerInvariant())) { Visit-Group $start $m ($path+$current) }
    }
}
foreach($g in $groups){ Visit-Group $g.dn $g.dn @() }
Add-RemainingControl 'vuln_group_loop' @(4) `
    "Boucle d'appartenance entre groupes" @($groupLoops | Sort-Object Path -Unique) `
    "Supprimer les cycles d'appartenance entre groupes." "$prefix\group.tsv"

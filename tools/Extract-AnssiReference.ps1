param(
    [Parameter(Mandatory)][string]$ChecklistPath,
    [Parameter(Mandatory)][string]$OutputPath
)

$source = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ChecklistPath))
$aliases = @{}
foreach ($alias in [regex]::Matches($source, '(?:const |,)([A-Za-z_$][A-Za-z0-9_$]*)=([A-Za-z_$][A-Za-z0-9_$]*)(?=[;,])')) {
    $aliases[$alias.Groups[1].Value] = $alias.Groups[2].Value
}
function Resolve-ComponentVariable([string]$Variable) {
    $seen = @{}
    while ($aliases.ContainsKey($Variable) -and -not $seen.ContainsKey($Variable)) {
        $seen[$Variable] = $true
        $Variable = $aliases[$Variable]
    }
    return $Variable
}
$variableToId = @{}
foreach ($match in [regex]::Matches($source, '(vuln_[a-z0-9_]+):([A-Za-z_$][A-Za-z0-9_$]*)')) {
    $variableToId[(Resolve-ComponentVariable $match.Groups[2].Value)] = $match.Groups[1].Value
}
function Convert-JsText([string]$Value) {
    if ($null -eq $Value) { return '' }
    return $Value.Replace('\n', ' ').Replace('\"', '"').Replace("\'", "'").Replace('\\', '\')
}

function Get-PartText([string]$Segment, [string]$Part, [string]$NextPart) {
    $start = $Segment.IndexOf(('"{0}"' -f $Part))
    if ($start -lt 0) { return '' }
    $end = if ($NextPart) { $Segment.IndexOf(('"{0}"' -f $NextPart), $start + 1) } else { $Segment.Length }
    if ($end -lt 0) { $end = $Segment.Length }
    $partText = $Segment.Substring($start, $end - $start)
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($partText, 'children:"((?:\\.|[^"\\])*)"')) {
        $values.Add((Convert-JsText $m.Groups[1].Value))
    }
    foreach ($m in [regex]::Matches($partText, "children:'((?:\\.|[^'\\])*)'")) {
        $values.Add((Convert-JsText $m.Groups[1].Value))
    }
    return (($values | Where-Object { $_ }) -join "`n").Trim()
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($gradeMatch in [regex]::Matches($source, 'b\(([A-Za-z_$][A-Za-z0-9_$]*),"grades",\[([^\]]*)\]\)')) {
    $variable = $gradeMatch.Groups[1].Value
    if (-not $variableToId.ContainsKey($variable)) { continue }
    # Le minifieur déclare ensuite certains composants dans une déclaration séparée par des virgules.
    $start = $source.LastIndexOf(('{0}=function' -f $variable), $gradeMatch.Index)
    if ($start -lt 0) { continue }
    $segment = $source.Substring($start, $gradeMatch.Index - $start)
    $results.Add([pscustomobject]@{
        Id = $variableToId[$variable]
        Levels = $gradeMatch.Groups[2].Value
        Title = Get-PartText $segment 'title_fr' 'title_en'
        Description = Get-PartText $segment 'vuln_fr' 'vuln_en'
        Recommendation = Get-PartText $segment 'reco_fr' 'reco_en'
    })
}

# Second passage par association locale : les noms minifiés sont réutilisés entre modules.
$knownIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($result in $results) { [void]$knownIds.Add($result.Id) }
foreach ($mapMatch in [regex]::Matches($source, '(vuln_[a-z0-9_]+):([A-Za-z_$][A-Za-z0-9_$]*)')) {
    $id = $mapMatch.Groups[1].Value
    if ($knownIds.Contains($id) -or $id -in @('vuln_fr','vuln_en','vuln_rp','vuln_table')) { continue }
    $variable = $mapMatch.Groups[2].Value
    $windowStart = [Math]::Max(0, $mapMatch.Index - 150000)
    $beforeMap = $source.Substring($windowStart, $mapMatch.Index - $windowStart)
    $seen = @{}
    while (-not $seen.ContainsKey($variable)) {
        $seen[$variable] = $true
        $aliasMatches = [regex]::Matches($beforeMap, ('(?:const |,){0}=([A-Za-z_$][A-Za-z0-9_$]*)(?=[;,])' -f [regex]::Escape($variable)))
        if (-not $aliasMatches.Count) { break }
        $variable = $aliasMatches[$aliasMatches.Count - 1].Groups[1].Value
    }
    $gradeMatches = [regex]::Matches($beforeMap, ('b\({0},"grades",\[([^\]]*)\]\)' -f [regex]::Escape($variable)))
    if (-not $gradeMatches.Count) { continue }
    $localGrade = $gradeMatches[$gradeMatches.Count - 1]
    $gradeIndex = $windowStart + $localGrade.Index
    $start = $source.LastIndexOf(('{0}=function' -f $variable), $gradeIndex)
    if ($start -lt 0) { continue }
    $segment = $source.Substring($start, $gradeIndex - $start)
    $results.Add([pscustomobject]@{
        Id = $id
        Levels = $localGrade.Groups[1].Value
        Title = Get-PartText $segment 'title_fr' 'title_en'
        Description = Get-PartText $segment 'vuln_fr' 'vuln_en'
        Recommendation = Get-PartText $segment 'reco_fr' 'reco_en'
    })
    [void]$knownIds.Add($id)
}
$results | Sort-Object Id -Unique | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output "Extracted=$(@($results | Sort-Object Id -Unique).Count)"

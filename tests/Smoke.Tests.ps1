$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$sample = Join-Path $project 'oradad-out'
if (-not (Test-Path -LiteralPath $sample)) {
    $sample = Join-Path $project 'Vertou-out'
}
$out = Join-Path $env:TEMP ('ads-open-smoke-' + [guid]::NewGuid())

try {
    & (Join-Path $project 'ADS-Open.ps1') -InputPath $sample -OutputPath $out -Format Both | Out-Null
    if (-not (Test-Path (Join-Path $out 'report.json'))) { throw 'report.json absent' }
    if (-not (Test-Path (Join-Path $out 'report.html'))) { throw 'report.html absent' }
    $report = Get-Content (Join-Path $out 'report.json') -Raw | ConvertFrom-Json
    if ($report.Controls.Count -ne 76) { throw "Catalogue ANSSI incomplet: $($report.Controls.Count)/76" }
    if (@($report.Controls.Id | Sort-Object -Unique).Count -ne 76) { throw 'Identifiants ANSSI dupliqués' }
    if (@($report.Controls | Where-Object Status -eq 'NotEvaluated').Count -ne 0) {
        throw 'Des contrôles sont encore non évalués'
    }
    if (@($report.Controls | Where-Object Implementation -ne 'Implemented').Count -ne 0) {
        throw 'Des contrôles ne disposent pas encore de moteur implémenté'
    }
    $catalog = Import-Csv (Join-Path $project 'data\anssi-controls.tsv') -Delimiter "`t"
    foreach ($expected in $catalog) {
        $actual = $report.Controls | Where-Object Id -eq $expected.Id | Select-Object -First 1
        $actualLevels = @($actual.Levels | ForEach-Object { [string]$_ }) -join ','
        if ($actualLevels -ne $expected.Levels) {
            throw "Niveau ANSSI divergent pour $($expected.Id): rapport=$actualLevels catalogue=$($expected.Levels)"
        }
    }
    foreach ($id in @(
        'vuln_permissions_gmsa_keys',
        'vuln_permissions_msdns',
        'vuln_permissions_naming_context',
        'vuln_permissions_dc',
        'vuln_permissions_dfsr_sysvol',
        'vuln_adcs_template_control',
        'vuln_adcs_template_auth_enroll_with_name',
        'vuln_rodc_denied_group'
    )) {
        $control = $report.Controls | Where-Object Id -eq $id | Select-Object -First 1
        if ($control.Status -ne 'Passed') {
            throw "$id doit ignorer les ACE des groupes opératifs intégrés vides dans l'extract de test"
        }
    }
    $heuristics = $report.Controls | Where-Object Id -eq 'vuln_dsheuristics_bad' | Select-Object -First 1
    if ($heuristics.Status -ne 'Failed' -or (@($heuristics.FailedLevels) -join ',') -ne '4') {
        throw 'dSHeuristics par défaut doit uniquement échouer au seuil de durcissement ANSSI niveau 4'
    }
    if ($report.Score.Level -notin 1..5) { throw 'Niveau invalide' }
    "OK - $($report.Controls.Count) contrôles, niveau $($report.Score.Level)"
}
finally {
    if (Test-Path $out) { Remove-Item -LiteralPath $out -Recurse -Force }
}

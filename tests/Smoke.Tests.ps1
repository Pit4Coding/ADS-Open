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
    if ($report.Version -ne '1.3.1') { throw "Version ADS-Open inattendue: $($report.Version)" }
    $html = Get-Content (Join-Path $out 'report.html') -Raw
    if ($html -notmatch 'Version ADS-Open</span><b>v1\.3\.1</b>') {
        throw 'Version ADS-Open absente de l''en-tête HTML'
    }
    if ($report.Advisories.Count -ne 50) { throw "Catalogue complémentaire ANSSI incomplet: $($report.Advisories.Count)/50" }
    if (@($report.Advisories | Where-Object Type -eq 'Warning').Count -ne 37) { throw 'Nombre d''avertissements ANSSI invalide' }
    if (@($report.Advisories | Where-Object Type -eq 'Information').Count -ne 13) { throw 'Nombre d''informations ANSSI invalide' }
    if (@($report.Advisories | Where-Object { -not $_.PublishedDate }).Count -ne 0) { throw 'Un item complémentaire ne possède pas de date ANSSI publiée' }
    if (@($report.Advisories | Where-Object { -not $_.Explanation -or -not $_.ResultSummary }).Count -ne 0) { throw 'Un item complémentaire ne possède pas d''explication ou de résultat' }
    if (@($report.Advisories | Where-Object AffectsScore).Count -ne 0) { throw 'Un item complémentaire influence la note' }
    if (@($report.Controls | Where-Object { $_.Type -ne 'Vulnerability' -or -not $_.AffectsScore }).Count -ne 0) { throw 'Classification des vulnérabilités invalide' }
    $datedWarning = $report.Advisories | Where-Object Id -eq 'warning_admincount' | Select-Object -First 1
    if ($datedWarning.PublishedDate -ne '2018-09-27') { throw 'Date ANSSI de warning_admincount invalide' }
    if ($html -notmatch 'Observations complémentaires ANSSI' -or $html -notmatch 'Avertissements ANSSI' -or $html -notmatch 'Informations ANSSI') { throw 'Sections complémentaires absentes du rapport HTML' }
    if ($html -notmatch 'overflow-wrap:anywhere' -or $html -notmatch 'minmax\(min\(100%,340px\),1fr\)') { throw 'Protection responsive des cartes absente' }
    if ($report.Controls.Count -ne 76) { throw "Catalogue ANSSI incomplet: $($report.Controls.Count)/76" }
    if (@($report.Controls.Id | Sort-Object -Unique).Count -ne 76) { throw 'Identifiants ANSSI dupliqués' }
    if (@($report.Controls | Where-Object Status -eq 'NotEvaluated').Count -ne 0) {
        throw 'Des contrôles sont encore non évalués'
    }
    if (@($report.Controls | Where-Object Implementation -ne 'Implemented').Count -ne 0) {
        throw 'Des contrôles ne disposent pas encore de moteur implémenté'
    }
    if (@($report.Controls | Where-Object { -not $_.DetailedDescription -or -not $_.OfficialRecommendation -or -not $_.GuidanceReviewedOn }).Count -ne 0) {
        throw 'Des contrôles ne disposent pas de leur fiche détaillée ANSSI'
    }
    if ($html -notmatch 'Description détaillée' -or $html -notmatch 'Recommandations, annotations, limites et acceptations') {
        throw 'Les fiches détaillées ANSSI sont absentes du rapport HTML'
    }
    if ($html -match 'cert\.ssi\.gouv\.fr' -or $html -match 'target="_blank"') {
        throw 'Le rapport HTML contient encore un lien externe ANSSI'
    }
    if ($html -notmatch 'Copie locale du référentiel ANSSI' -or $html -notmatch 'anssi-callout') {
        throw 'La restitution hors ligne structurée du référentiel ANSSI est absente'
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

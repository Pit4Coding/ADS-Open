Set-StrictMode -Version 2.0

function Get-ADSOpenControlDefinitions {
    param([Parameter(Mandatory)][string]$ControlsPath)

    $definitions = @(
        Get-ChildItem -LiteralPath $ControlsPath -Filter 'vuln_*.ps1' -File |
            Sort-Object Name |
            ForEach-Object { & $_.FullName }
    )
    $duplicates = @($definitions | Group-Object Id | Where-Object Count -gt 1)
    if ($duplicates.Count) {
        throw "Définitions de contrôles dupliquées : $($duplicates.Name -join ', ')"
    }
    return $definitions
}

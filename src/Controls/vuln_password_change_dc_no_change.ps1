param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_dc_no_change'
        Levels = [int[]]@(1)
        Title = 'Contrôleurs de domaine dont le mot de passe de compte d''ordinateur est inchangé depuis plus de 45 jours'
    }
}

$dcOldPassword = @($computers | Where-Object {
    $_.primaryGroupID -in @('516','521') -and (Convert-OradadDate $_.pwdLastSet) -lt $now.AddDays(-45)
} | Select-Object dn, sAMAccountName, pwdLastSet, operatingSystem)
$results.Add((New-ControlResult 'vuln_password_change_dc_no_change' @(1) "Contrôleurs de domaine dont le mot de passe est inchangé depuis plus de 45 jours" `
    $(if ($dcOldPassword.Count) { 'Failed' } else { 'Passed' }) $dcOldPassword `
    'Diagnostiquer Netlogon et rétablir la rotation automatique du secret du compte machine.' "$prefix\computer.tsv"))

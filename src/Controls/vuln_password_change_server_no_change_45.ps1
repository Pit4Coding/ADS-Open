param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_server_no_change_45'
        Levels = [int[]]@(3)
        Title = 'Serveurs dont le mot de passe de compte d''ordinateur est inchangé depuis plus de 45 jours'
    }
}

$servers = @($computers | Where-Object {
    -not (Test-UacFlag $_ 2) -and $_.primaryGroupID -notin @('516','521') -and
    $_.operatingSystem -match 'Server'
})
$server45 = @($servers | Where-Object {
    (Convert-OradadDate $_.pwdLastSet) -lt $now.AddDays(-45)
} | Select-Object dn, sAMAccountName, pwdLastSet, operatingSystem)
$results.Add((New-ControlResult 'vuln_password_change_server_no_change_45' @(3) "Serveurs dont le mot de passe de compte d'ordinateur est inchangé depuis plus de 45 jours" `
    $(if ($server45.Count) { 'Failed' } else { 'Passed' }) $server45 `
    'Diagnostiquer la rotation du secret machine des serveurs concernés.' "$prefix\computer.tsv"))

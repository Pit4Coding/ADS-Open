param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_password_change_server_no_change_90'
        Levels = [int[]]@(2)
        Title = 'Serveurs dont le mot de passe de compte d''ordinateur est inchangé depuis plus de 90 jours'
    }
}

$server90 = @($server45 | Where-Object {
    (Convert-OradadDate $_.pwdLastSet) -lt $now.AddDays(-90)
})
$results.Add((New-ControlResult 'vuln_password_change_server_no_change_90' @(2) "Serveurs dont le mot de passe de compte d'ordinateur est inchangé depuis plus de 90 jours" `
    $(if ($server90.Count) { 'Failed' } else { 'Passed' }) $server90 `
    'Rétablir sans délai la rotation du secret machine des serveurs concernés.' "$prefix\computer.tsv"))

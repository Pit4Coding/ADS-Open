param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_dont_expire'
        Levels = [int[]]@(2)
        Title = 'Comptes dont le mot de passe n''expire jamais'
    }
}

$neverExpire = @($users | Where-Object {
    -not (Test-UacFlag $_ 2) -and (Test-UacFlag $_ 65536)
} | Select-Object dn, sAMAccountName, adminCount, pwdLastSet)
$activeUsers = @($users | Where-Object { -not (Test-UacFlag $_ 2) })
$neverExpireThresholdExceeded = $activeUsers.Count -gt 0 -and
    (($neverExpire.Count / $activeUsers.Count) -gt 0.10)
$neverExpireFindings = if ($neverExpireThresholdExceeded) { $neverExpire } else { @() }
$results.Add((New-ControlResult 'vuln_dont_expire' @(2) "Comptes dont le mot de passe n'expire jamais" `
    $(if ($neverExpireThresholdExceeded) { 'Failed' } else { 'Passed' }) $neverExpireFindings `
    "Retirer l'option d'expiration désactivée, hors exception documentée et compensée." "$prefix\user.tsv"))

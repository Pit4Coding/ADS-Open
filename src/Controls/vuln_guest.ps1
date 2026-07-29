param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_guest'
        Levels = [int[]]@(2)
        Title = 'Compte Invité actif'
    }
}

$guest = @($users | Where-Object {
    $_.objectSid -match '-501$' -and -not (Test-UacFlag $_ 2)
} | Select-Object dn, sAMAccountName, userAccountControl)
$results.Add((New-ControlResult 'vuln_guest' @(2) 'Compte Invité actif' `
    $(if ($guest.Count) { 'Failed' } else { 'Passed' }) $guest `
    'Désactiver le compte Invité du domaine.' "$prefix\user.tsv"))

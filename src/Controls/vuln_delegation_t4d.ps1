param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_delegation_t4d'
        Levels = [int[]]@(1)
        Title = 'Délégation d''authentification non contrainte'
    }
}

$delegation = @($computers + $users | Where-Object {
    -not (Test-UacFlag $_ 2) -and $_.primaryGroupID -notin @('516','521') -and
    (Test-UacFlag $_ 524288)
} | Select-Object dn, sAMAccountName, userAccountControl)
$results.Add((New-ControlResult 'vuln_delegation_t4d' @(1) "Délégation d'authentification non contrainte" `
    $(if ($delegation.Count) { 'Failed' } else { 'Passed' }) $delegation `
    'Supprimer la délégation non contrainte et migrer vers une délégation limitée et justifiée.' "$prefix\user.tsv; $prefix\computer.tsv"))

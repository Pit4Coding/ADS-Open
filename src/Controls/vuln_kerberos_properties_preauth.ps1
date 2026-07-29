param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_kerberos_properties_preauth'
        Levels = [int[]]@(2)
        Title = 'Comptes sans préauthentification Kerberos'
    }
}

$noPreauth = @($users | Where-Object {
    -not (Test-UacFlag $_ 2) -and (Test-UacFlag $_ 4194304)
} | Select-Object dn, sAMAccountName, adminCount)
$results.Add((New-ControlResult 'vuln_kerberos_properties_preauth' @(2) 'Comptes sans préauthentification Kerberos' `
    $(if ($noPreauth.Count) { 'Failed' } else { 'Passed' }) $noPreauth `
    'Réactiver la préauthentification Kerberos sauf nécessité technique formellement justifiée.' "$prefix\user.tsv"))

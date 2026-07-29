param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_spn_priv'
        Levels = [int[]]@(1)
        Title = 'Comptes privilégiés avec SPN'
    }
}

$spnPriv = @($users | Where-Object {
    -not (Test-UacFlag $_ 2) -and $_.dn -in $privilegedAccountDnsForRules -and $_.servicePrincipalName
} | Select-Object dn, sAMAccountName, servicePrincipalName)
$results.Add((New-ControlResult 'vuln_spn_priv' @(1) 'Comptes privilégiés avec SPN' `
    $(if ($spnPriv.Count) { 'Failed' } else { 'Passed' }) $spnPriv `
    'Retirer les SPN des comptes privilégiés et employer des comptes de service dédiés ou gMSA.' "$prefix\user.tsv"))

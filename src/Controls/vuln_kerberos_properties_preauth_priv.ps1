param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_kerberos_properties_preauth_priv'
        Levels = [int[]]@(1)
        Title = 'Comptes privilégiés sans préauthentification Kerberos'
    }
}

$noPreauthPriv = @($noPreauth | Where-Object dn -in $privilegedAccountDnsForRules)
$results.Add((New-ControlResult 'vuln_kerberos_properties_preauth_priv' @(1) 'Comptes privilégiés sans préauthentification Kerberos' `
    $(if ($noPreauthPriv.Count) { 'Failed' } else { 'Passed' }) $noPreauthPriv `
    'Réactiver immédiatement la préauthentification Kerberos sur les comptes privilégiés.' "$prefix\user.tsv"))

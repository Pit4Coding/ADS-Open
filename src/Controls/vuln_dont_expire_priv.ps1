param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_dont_expire_priv'
        Levels = [int[]]@(1)
        Title = 'Comptes privilégiés dont le mot de passe n''expire jamais'
    }
}

$privilegedAccountDnsForRules = @($privilegedAccounts | ForEach-Object dn)
$neverExpirePriv = @($neverExpire | Where-Object dn -in $privilegedAccountDnsForRules)
$results.Add((New-ControlResult 'vuln_dont_expire_priv' @(1) "Comptes privilégiés dont le mot de passe n'expire jamais" `
    $(if ($neverExpirePriv.Count) { 'Failed' } else { 'Passed' }) $neverExpirePriv `
    "Imposer une rotation maîtrisée des secrets de tous les comptes privilégiés." "$prefix\user.tsv"))

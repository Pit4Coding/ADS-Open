param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_reversible_password_priv_uac'
        Levels = [int[]]@(3)
        Title = 'Comptes privilégiés ayant leur mot de passe stocké de manière réversible'
    }
}

$reversible = @($users | Where-Object {
    -not (Test-UacFlag $_ 2) -and $_.dn -in $privilegedAccountDnsForRules -and (Test-UacFlag $_ 128)
} | Select-Object dn, sAMAccountName)
$results.Add((New-ControlResult 'vuln_reversible_password_priv_uac' @(3) 'Comptes privilégiés ayant leur mot de passe stocké de manière réversible' `
    $(if ($reversible.Count) { 'Failed' } else { 'Passed' }) $reversible `
    'Désactiver le stockage réversible et renouveler immédiatement les mots de passe concernés.' "$prefix\user.tsv"))

param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_silo_priv'
        Levels = [int[]]@(4)
        Title = 'Membres des groupes privilégiés hors silo d''authentification'
    }
}

$enforcedSiloDns = @($authPolicySilos | Where-Object {
    $_.'msDS-AuthNPolicySiloEnforced' -in @('1','TRUE','True','true')
} | ForEach-Object dn)
$outsideSilo = @($privilegedAccounts | Where-Object {
    (Get-PrincipalRid $_) -ne '500' -and (
        -not $_.'msDS-AssignedAuthNPolicySilo' -or
        $_.'msDS-AssignedAuthNPolicySilo' -notin $enforcedSiloDns
    )
} |
    Select-Object dn, sAMAccountName, 'msDS-AssignedAuthNPolicySilo')
$results.Add((New-ControlResult 'vuln_silo_priv' @(4) "Membres des groupes privilégiés hors silo d'authentification" `
    $(if ($outsideSilo.Count) { 'Failed' } else { 'Passed' }) $outsideSilo `
    "Affecter les comptes privilégiés à un silo d'authentification appliqué et correctement configuré." "$prefix\user.tsv; $prefix\group.tsv"))

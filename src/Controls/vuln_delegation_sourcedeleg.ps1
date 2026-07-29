param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_delegation_sourcedeleg'
        Levels = [int[]]@(1)
        Title = 'Délégation contrainte basée sur la ressource vers des services privilégiés'
    }
}

$rbcdPrivilegedTargets = @(
    $computers | Where-Object primaryGroupID -in @('516','521')
    $privilegedAccounts
    $users | Where-Object objectSid -match '-502$'
)
$rbcd = @($rbcdPrivilegedTargets | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
    Select-Object dn, sAMAccountName, 'msDS-AllowedToActOnBehalfOfOtherIdentity')
$results.Add((New-ControlResult 'vuln_delegation_sourcedeleg' @(1) 'Délégation contrainte basée sur la ressource vers des services privilégiés' `
    $(if ($rbcd.Count) { 'Failed' } else { 'Passed' }) $rbcd `
    'Qualifier les délégations RBCD et supprimer celles qui ciblent des ressources privilégiées.' "$prefix\user.tsv; $prefix\computer.tsv"))

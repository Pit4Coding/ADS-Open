param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_user_accounts_machineaccountquota'
        Levels = [int[]]@(4)
        Title = 'Ajout de machines au domaine non limité'
    }
}

$maq = @($roots | Where-Object {
    $v = 0
    [int]::TryParse([string]$_.'ms-DS-MachineAccountQuota', [ref]$v) -and $v -gt 0
} | Select-Object dn, 'ms-DS-MachineAccountQuota')
$results.Add((New-ControlResult 'vuln_user_accounts_machineaccountquota' @(4) 'Ajout de machines au domaine non limité' `
    $(if ($maq.Count) { 'Failed' } else { 'Passed' }) $maq `
    'Positionner ms-DS-MachineAccountQuota à 0 et déléguer explicitement les jonctions au domaine.' "$prefix\root.tsv"))

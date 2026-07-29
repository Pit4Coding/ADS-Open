param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_user_accounts_dormant'
        Levels = [int[]]@(1)
        Title = 'Nombre important de comptes actifs inutilisés'
    }
}

$dormantCandidates = @($users+$computers | Where-Object { -not (Test-UacFlag $_ 2) })
$dormant = @($dormantCandidates | Where-Object {
    $pwd=Convert-OradadDate $_.pwdLastSet
    $logon=Convert-OradadDate $_.lastLogonTimestamp
    $pwd -and $pwd -lt $now.AddYears(-3) -and (-not $logon -or $logon -lt $now.AddYears(-1))
} | Select-Object dn,sAMAccountName,pwdLastSet,lastLogonTimestamp)
$dormantFinding = if ($dormantCandidates.Count -and
    ($dormant.Count / $dormantCandidates.Count) -gt .25) { $dormant } else { @() }
Add-RemainingControl 'vuln_user_accounts_dormant' @(1) `
    'Proportion excessive de comptes dormants' $dormantFinding `
    'Désactiver ou supprimer les comptes durablement inactifs.' `
    "$prefix\user.tsv; $prefix\computer.tsv"

param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_privileged_members_password'
        Levels = [int[]]@(2)
        Title = 'Comptes membres de groupes privilégiés avec une mauvaise politique de mot de passe'
    }
}

function Test-WeakPrivilegedPasswordPolicy {
    param($Policy,[bool]$FineGrained)
    if ($FineGrained) {
        $minimumLength = Get-Integer $Policy.'msDS-MinimumPasswordLength'
        $maximumAge = [math]::Abs([double](Get-Integer $Policy.'msDS-MaximumPasswordAge_int'))
    } else {
        $minimumLength = Get-Integer $Policy.minPwdLength
        $maximumAge = [math]::Abs([double](Get-Integer $Policy.maxPwdAge_int))
    }
    $maximumAgeDays = if ($maximumAge -gt 0) { $maximumAge / 864000000000 } else { [double]::PositiveInfinity }
    return $minimumLength -lt 8 -or $maximumAgeDays -gt (365.25 * 3)
}
$psoByDn = @{}
foreach ($pso in $passwordSettings) { if ($pso.dn) { $psoByDn[$pso.dn.ToLowerInvariant()] = $pso } }
$domainPasswordPolicy = $roots | Select-Object -First 1
$weakPrivPassword = @($privilegedAccounts | Where-Object {
    $psoDn = [string](Get-OradadValue $_ 'msDS-ResultantPSO')
    if ($psoDn -and $psoByDn.ContainsKey($psoDn.ToLowerInvariant())) {
        Test-WeakPrivilegedPasswordPolicy $psoByDn[$psoDn.ToLowerInvariant()] $true
    } else {
        Test-WeakPrivilegedPasswordPolicy $domainPasswordPolicy $false
    }
} | Select-Object dn,sAMAccountName,'msDS-ResultantPSO')
Add-RemainingControl 'vuln_privileged_members_password' @(2) `
    'Stratégie de mot de passe insuffisante pour des comptes privilégiés' $weakPrivPassword `
    'Appliquer une stratégie renforcée aux comptes privilégiés.' `
    "$prefix\passwordSettings.tsv; $prefix\user.tsv"

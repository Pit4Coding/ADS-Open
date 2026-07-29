param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_dsheuristics_bad'
        Levels = [int[]]@(1,2,4)
        Title = 'Paramètres dSHeuristics dangereux'
    }
}

$heuristicFindings = [System.Collections.Generic.List[object]]::new()
foreach ($service in $ntdsServices) {
    $value = [string]$service.dSHeuristics
    function Get-HeuristicCharacter([int]$Position) {
        if ($value.Length -ge $Position) { return [string]$value[$Position-1] }
        return '0'
    }
    $checks = @(
        @{Position=8;  Name='fAllowAnonNSPI'; Bad={param($v) $v -ne '0'}; Level=1}
        @{Position=16; Name='dwAdminSDExMask'; Bad={param($v) $v -ne '0'}; Level=1}
        @{Position=7;  Name='fLDAPBlockAnonOps'; Bad={param($v) $v -eq '2'}; Level=2}
        @{Position=21; Name='DoNotVerifyUPNAndOrSPNUniqueness'; Bad={param($v) $v -ne '0'}; Level=2}
        @{Position=28; Name='AttributeAuthorizationOnLDAPAdd'; Bad={param($v) $v -eq '2'}; Level=2}
        @{Position=29; Name='BlockOwnerImplicitRights'; Bad={param($v) $v -eq '2'}; Level=2}
        @{Position=31; Name='DisableConfidentialAttributeEncryptionRequirements'; Bad={param($v) $v -ne '0'}; Level=2}
        @{Position=28; Name='AttributeAuthorizationOnLDAPAdd'; Bad={param($v) $v -ne '1'}; Level=4}
        @{Position=29; Name='BlockOwnerImplicitRights'; Bad={param($v) $v -ne '1'}; Level=4}
    )
    foreach ($check in $checks) {
        $character = Get-HeuristicCharacter $check.Position
        if (& $check.Bad $character) {
            $heuristicFindings.Add([pscustomobject]@{
                Dn=$service.dn; Setting=$check.Name; Value=$character; Level=$check.Level
            })
        }
    }
}
$heuristicFailedLevels = @($heuristicFindings | ForEach-Object Level | Sort-Object -Unique)
$results.Add((New-ControlResult 'vuln_dsheuristics_bad' @(1,2,4) `
    'Valeurs dangereuses de dSHeuristics' `
    $(if ($heuristicFindings.Count) {'Failed'} else {'Passed'}) @($heuristicFindings) `
    "Rétablir les valeurs sûres de dSHeuristics documentées par l'ANSSI." `
    'configuration\nTDSService.tsv' 'Implemented' $heuristicFailedLevels))

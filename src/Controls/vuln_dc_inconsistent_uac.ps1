param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_dc_inconsistent_uac'; Levels=[int[]]@(1); Title='Contrôleurs de domaine incohérents' }
}

$serverByReference = @{}
foreach ($server in $servers) {
    $serverReference = [string](Get-OradadValue $server 'serverReference')
    if ($serverReference) { $serverByReference[$serverReference] = $server }
}
$ntdsByServerDn = @{}
foreach ($ntds in $ntdsDsas) {
    $ntdsDn = [string](Get-OradadValue $ntds 'dn')
    if ($ntdsDn -match '(?i)^CN=NTDS Settings,(.+)$') { $ntdsByServerDn[$Matches[1]] = $ntds }
}
$inconsistentDc = [System.Collections.Generic.List[object]]::new()
foreach ($computer in @($computers | Where-Object { $_.primaryGroupID -in @('516','521') })) {
    $reasons = [System.Collections.Generic.List[string]]::new()
    $isRodc = [string]$computer.primaryGroupID -eq '521'
    if ($isRodc) {
        if (-not (Test-UacFlag $computer 0x04000000)) { $reasons.Add('PARTIAL_SECRETS_ACCOUNT absent') }
        if (-not (Test-UacFlag $computer 0x01000000)) { $reasons.Add('TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION absent') }
        if (-not (Test-UacFlag $computer 0x00001000)) { $reasons.Add('WORKSTATION_TRUST_ACCOUNT absent') }
    } else {
        if (-not (Test-UacFlag $computer 0x00002000)) { $reasons.Add('SERVER_TRUST_ACCOUNT absent') }
        if (-not (Test-UacFlag $computer 0x00080000)) { $reasons.Add('TRUSTED_FOR_DELEGATION absent') }
    }
    $server = $serverByReference[[string]$computer.dn]
    if (-not $server) {
        $reasons.Add('Objet server avec serverReference correspondant absent')
    } else {
        $ntds = $ntdsByServerDn[[string]$server.dn]
        if (-not $ntds) {
            $reasons.Add('Objet fils NTDS Settings absent')
        } elseif ($isRodc -ne ([string](Get-OradadValue $ntds 'msDS-isRODC') -eq '1')) {
            $reasons.Add('Type nTDSDSA/nTDSDSARO incohérent avec le rôle DC/RODC')
        }
        if ($ntds -and (Get-OradadValue $computer 'operatingSystem') -match 'Windows Server (2008 R2|2012 R2|2008|2012|2016|2019|2022|2025)') {
            $expectedBehavior = switch ($Matches[1]) {
                '2008' { 3 }; '2008 R2' { 4 }; '2012' { 5 }; '2012 R2' { 6 }; '2025' { 10 }; default { 7 }
            }
            $actualBehavior = 0
            if (-not [int]::TryParse([string](Get-OradadValue $ntds 'msDS-Behavior-Version'), [ref]$actualBehavior) -or $actualBehavior -ne $expectedBehavior) {
                $reasons.Add("msDS-Behavior-Version=$(Get-OradadValue $ntds 'msDS-Behavior-Version') au lieu de $expectedBehavior")
            }
        }
    }
    if ($reasons.Count) {
        $inconsistentDc.Add([pscustomobject]@{
            dn=$computer.dn; sAMAccountName=$computer.sAMAccountName
            primaryGroupID=$computer.primaryGroupID; userAccountControl=$computer.userAccountControl
            Reasons=$reasons -join '; '
        })
    }
}
$results.Add((New-ControlResult 'vuln_dc_inconsistent_uac' @(1) 'Contrôleurs de domaine incohérents' `
    $(if ($inconsistentDc.Count) { 'Failed' } else { 'Passed' }) @($inconsistentDc) `
    'Rétablir les indicateurs UAC, les objets server/NTDS Settings et leur niveau fonctionnel conformément au rôle de chaque DC ou RODC.' "$prefix\computer.tsv; configuration\server.tsv; configuration\nTDSDSA.tsv"))
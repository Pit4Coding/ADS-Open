param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_dc_crypto'
        Levels = [int[]]@(2,3,4)
        Title = 'Algorithmes de chiffrement supportés par les DC/RODC'
    }
}

$dcCrypto = [System.Collections.Generic.List[object]]::new()
foreach ($dc in $computers | Where-Object primaryGroupID -in @('516','521')) {
    $encryption = [string]$dc.'msDS-SupportedEncryptionTypes'
    if ($encryption -match '(?i)DES') {
        $dcCrypto.Add([pscustomobject]@{Dn=$dc.dn;Algorithms=$encryption;Reason='DES activé';Level=2})
    }
    if (-not $encryption -or $encryption -notmatch '(?i)AES') {
        $dcCrypto.Add([pscustomobject]@{Dn=$dc.dn;Algorithms=$encryption;Reason='AES absent';Level=3})
    }
    if ($encryption -match '(?i)RC4') {
        $dcCrypto.Add([pscustomobject]@{Dn=$dc.dn;Algorithms=$encryption;Reason='RC4 activé';Level=4})
    }
}
$dcCryptoFailedLevels = @($dcCrypto | ForEach-Object Level | Sort-Object -Unique)
$results.Add((New-ControlResult 'vuln_dc_crypto' @(2,3,4) `
    'Algorithmes Kerberos faibles sur les contrôleurs de domaine' `
    $(if ($dcCrypto.Count) {'Failed'} else {'Passed'}) @($dcCrypto) `
    'Activer AES et désactiver DES et RC4 selon le niveau de durcissement visé.' `
    "$prefix\computer.tsv" 'Implemented' $dcCryptoFailedLevels))

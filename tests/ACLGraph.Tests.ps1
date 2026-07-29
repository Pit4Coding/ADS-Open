$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\ACLGraph.psm1') -Force

function Convert-SddlToHex([string]$Sddl) {
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    $bytes = New-Object byte[] $sd.BinaryLength
    $sd.GetBinaryForm($bytes, 0)
    return -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

$domainSid = 'S-1-5-21-1-2-3'
$attackerSid = "$domainSid-1100"
$targetDn = 'DC=example,DC=test'
$memberGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
$sddl = "O:SYD:(A;;GA;;;$attackerSid)(OA;;WP;$memberGuid;;$attackerSid)(A;;GA;;;$domainSid-512)"
$objects = @([pscustomobject]@{
    dn = $targetDn
    nTSecurityDescriptor = Convert-SddlToHex $sddl
})
$principals = @([pscustomobject]@{
    dn = 'CN=Attacker,DC=example,DC=test'
    objectSid = $attackerSid
})
$attributes = @([pscustomobject]@{
    schemaIDGUID = $memberGuid
    lDAPDisplayName = 'member'
    attributeSecurityGUID = ''
})

$analysis = Get-ADSOpenAclAnalysis -Objects $objects -Principals $principals `
    -Groups @() -Attributes $attributes -DomainSid $domainSid -Tier0Dns @($targetDn)

if (@($analysis.Relations | Where-Object Right -eq 'GenericAll').Count -ne 1) {
    throw 'GenericAll non détecté ou principal administratif non filtré'
}
if (@($analysis.Relations | Where-Object Right -eq 'WriteProperty:member').Count -ne 1) {
    throw "Écriture de l'attribut member non détectée"
}
if (@($analysis.Paths).Count -lt 1) {
    throw 'Chemin de contrôle vers Tier 0 non construit'
}
if ($analysis.ParseErrors.Count) {
    throw 'Erreur de décodage inattendue'
}

"OK - moteur ACL: $($analysis.Relations.Count) relations, $($analysis.Paths.Count) chemin(s)"

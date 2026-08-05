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
    -Groups @() -Attributes $attributes -DomainSid $domainSid -Tier0Dns @($targetDn) -IncludePaths

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

# Un refus spécifique doit neutraliser le droit, y compris lorsque celui-ci
# provient d'une autorisation générique qui doit d'abord être développée.
$denyDeleteSddl = 'O:SYD:(D;;DC;;;WD)(A;;GA;;;WD)'
$denyDeleteObjects = @([pscustomobject]@{
    dn = $targetDn
    nTSecurityDescriptor = Convert-SddlToHex $denyDeleteSddl
})
$denyDeleteAnalysis = Get-ADSOpenAclAnalysis -Objects $denyDeleteObjects -Principals $principals `
    -Groups @() -Attributes $attributes -DomainSid $domainSid -Tier0Dns @($targetDn)
if (@($denyDeleteAnalysis.Relations | Where-Object Right -eq 'DeleteChild').Count) {
    throw 'DeleteChild refusé a été comptabilisé comme accordé'
}
if (@($denyDeleteAnalysis.Relations | Where-Object Right -eq 'GenericAll').Count) {
    throw 'GenericAll ne doit pas subsister intégralement après un refus DeleteChild'
}
if (-not @($denyDeleteAnalysis.Relations | Where-Object Right -eq 'WriteDacl').Count) {
    throw 'Les autres droits réellement accordés par GenericAll doivent être conservés'
}

$denyExactSddl = "O:SYD:(D;;DC;;;$attackerSid)(A;;DC;;;$attackerSid)"
$denyExactObjects = @([pscustomobject]@{
    dn = $targetDn
    nTSecurityDescriptor = Convert-SddlToHex $denyExactSddl
})
$denyExactAnalysis = Get-ADSOpenAclAnalysis -Objects $denyExactObjects -Principals $principals `
    -Groups @() -Attributes $attributes -DomainSid $domainSid -Tier0Dns @($targetDn)
if ($denyExactAnalysis.Relations.Count) {
    throw 'Une autorisation entièrement neutralisée par un refus ne doit produire aucune relation'
}

$adminSdHolder = [pscustomobject]@{
    nTSecurityDescriptor = Convert-SddlToHex 'O:SYD:P(A;;GA;;;SY)'
}
$protectedAccount = [pscustomobject]@{
    nTSecurityDescriptor = Convert-SddlToHex 'O:SYD:P(A;;GA;;;SY)'
}
if (-not (Test-ADSOpenAdminSdHolderProtection -Object $protectedAccount -AdminSdHolder $adminSdHolder)) {
    throw 'Une DACL protégée identique à AdminSDHolder doit être reconnue'
}
$inheritingAccount = [pscustomobject]@{
    nTSecurityDescriptor = Convert-SddlToHex 'O:SYD:(A;;GA;;;SY)'
}
if (Test-ADSOpenAdminSdHolderProtection -Object $inheritingAccount -AdminSdHolder $adminSdHolder) {
    throw 'Une DACL avec héritage actif ne doit pas être reconnue comme protégée'
}
$dangerousExtraAce = [pscustomobject]@{
    nTSecurityDescriptor = Convert-SddlToHex 'O:SYD:P(A;;GA;;;SY)(A;;GA;;;WD)'
}
if (Test-ADSOpenAdminSdHolderProtection -Object $dangerousExtraAce -AdminSdHolder $adminSdHolder) {
    throw 'Une ACE dangereuse absente de AdminSDHolder ne doit pas être tolérée'
}
$benignSelfAce = [pscustomobject]@{
    nTSecurityDescriptor = Convert-SddlToHex 'O:SYD:P(A;;GA;;;SY)(A;;RP;;;PS)'
}
if (-not (Test-ADSOpenAdminSdHolderProtection -Object $benignSelfAce -AdminSdHolder $adminSdHolder)) {
    throw 'Une ACE bénigne pour SELF doit être tolérée'
}
$benignEnterpriseDcAce = [pscustomobject]@{
    nTSecurityDescriptor = Convert-SddlToHex 'O:SYD:P(A;;GA;;;SY)(A;;RP;;;S-1-5-9)'
}
if (-not (Test-ADSOpenAdminSdHolderProtection -Object $benignEnterpriseDcAce -AdminSdHolder $adminSdHolder)) {
    throw 'Une ACE bénigne pour Enterprise Domain Controllers doit être tolérée'
}
$benignSendToAce = [pscustomobject]@{
    nTSecurityDescriptor = Convert-SddlToHex 'O:SYD:P(A;;GA;;;SY)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;WD)'
}
if (-not (Test-ADSOpenAdminSdHolderProtection -Object $benignSendToAce -AdminSdHolder $adminSdHolder)) {
    throw 'Le droit étendu bénin Send-To doit être toléré'
}

"OK - moteur ACL: $($analysis.Relations.Count) relations, $($analysis.Paths.Count) chemin(s)"

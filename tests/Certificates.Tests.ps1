$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $project 'src\ADSOpen.psm1') -Force
$module = Get-Module ADSOpen
$reference = [datetime]'2026-08-16T12:00:00Z'

function Test-CertificateScope([datetime]$NotAfter, [string]$HolderDn) {
    $certificate = [pscustomobject]@{ NotAfter = $NotAfter }
    & $module {
        param($Cert,$Dn,$At)
        Test-ADSOpenCertificateInScope -Certificate $Cert -HolderDn $Dn -ReferenceTime $At
    } $certificate $HolderDn $reference
}

$validUntil = $reference.AddDays(1)
$expiredAt = $reference.AddDays(-1)

if (-not (Test-CertificateScope $validUntil 'CN=Alice,CN=Users,DC=example,DC=test')) {
    throw 'Un certificat utilisateur valide doit rester analysé'
}
if (Test-CertificateScope $expiredAt 'CN=Alice,CN=Users,DC=example,DC=test') {
    throw 'Un certificat utilisateur expiré ne doit plus être analysé'
}
if (Test-CertificateScope $expiredAt 'CN=PC1,OU=Computers,DC=example,DC=test') {
    throw 'Un certificat machine expiré ne doit plus être analysé'
}
if (Test-CertificateScope $expiredAt 'CN=CA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test') {
    throw 'Un certificat expiré hors conteneur de confiance ne doit plus être analysé'
}
foreach ($trustedDn in @(
    'CN=RootCA,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test',
    'CN=IssuingCA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test',
    'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test'
)) {
    if (-not (Test-CertificateScope $expiredAt $trustedDn)) {
        throw "Un certificat expiré du conteneur de confiance doit rester analysé: $trustedDn"
    }
}

'OK - périmètre des certificats expirés'

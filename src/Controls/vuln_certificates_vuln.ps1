param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_certificates_vuln'
        Levels = [int[]]@(1,2,3)
        Title = 'Certificats faibles ou vulnérables'
    }
}

function Test-RocaPublicKey {
    param([byte[]]$Modulus)
    if (-not $Modulus -or $Modulus.Length -lt 128) { return $false }
    $littleEndian = New-Object byte[] ($Modulus.Length + 1)
    for ($i=0; $i -lt $Modulus.Length; $i++) {
        $littleEndian[$i] = $Modulus[$Modulus.Length - 1 - $i]
    }
    $number = New-Object System.Numerics.BigInteger -ArgumentList @(,$littleEndian)
    foreach ($prime in @(3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71)) {
        $allowed = [System.Collections.Generic.HashSet[int]]::new()
        $residue = 1
        while ($allowed.Add($residue)) { $residue = ($residue * (65537 % $prime)) % $prime }
        if (-not $allowed.Contains([int]($number % $prime))) { return $false }
    }
    return $true
}
$certBad=[System.Collections.Generic.List[object]]::new()
$seenCertificates = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach($holder in @($certificationAuthorities+$enrollmentServices+$users+$computers)){
    $rawCertificates = @(
        'cACertificate','userCertificate','userCert','userSMIMECertificate' | ForEach-Object {
            Split-MultiValue (Get-OradadValue $holder $_)
        }
    )
    foreach($raw in $rawCertificates){
        if (-not $raw -or -not $seenCertificates.Add($raw)) { continue }
        try {
            $bytes=New-Object byte[] ($raw.Length/2)
            for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[Convert]::ToByte($raw.Substring($i*2,2),16)}
            $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
            $sig=[string]$cert.SignatureAlgorithm.FriendlyName
            $signatureOid=[string]$cert.SignatureAlgorithm.Value
            $publicKeyOid=[string]$cert.PublicKey.Oid.Value
            $usesDsa = $publicKeyOid -eq '1.2.840.10040.4.1' -or
                $signatureOid -eq '1.2.840.10040.4.3' -or
                $signatureOid -like '2.16.840.1.101.3.4.3.*' -or
                $sig -match '(?i)\bDSA\b'
            if ($usesDsa) {
                $certBad.Add([pscustomobject]@{
                    Dn=$holder.dn
                    Subject=$cert.Subject
                    Reason="Algorithme DSA (signature $signatureOid, clé $publicKeyOid)"
                    Level=1
                })
            }
            $strongSignature = $sig -match '(?i)sha256|sha384|sha512|sha3'
            if(-not $strongSignature){
                $certBad.Add([pscustomobject]@{Dn=$holder.dn;Subject=$cert.Subject;Reason="Signature $sig";Level=3})
            }
            $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
            if($rsa){
                $parameters = $rsa.ExportParameters($false)
                if($rsa.KeySize -lt 1024){
                    $certBad.Add([pscustomobject]@{Dn=$holder.dn;Subject=$cert.Subject;Reason="RSA $($rsa.KeySize) bits";Level=1})
                } elseif($rsa.KeySize -lt 2048) {
                    $certBad.Add([pscustomobject]@{Dn=$holder.dn;Subject=$cert.Subject;Reason="RSA $($rsa.KeySize) bits";Level=3})
                }
                $exponent = 0L
                foreach ($b in $parameters.Exponent) { $exponent = ($exponent * 256) + $b }
                if ($exponent -lt 65537) {
                    $certBad.Add([pscustomobject]@{Dn=$holder.dn;Subject=$cert.Subject;Reason="Exposant RSA $exponent";Level=3})
                }
                if (Test-RocaPublicKey $parameters.Modulus) {
                    $certBad.Add([pscustomobject]@{Dn=$holder.dn;Subject=$cert.Subject;Reason='Clé RSA vulnérable à ROCA';Level=1})
                }
            }
        } catch {
            $certBad.Add([pscustomobject]@{Dn=$holder.dn;Subject='';Reason='Certificat indécodable';Level=2})
        }
    }
}
$certificateFailedLevels = @($certBad | ForEach-Object Level | Sort-Object -Unique)
$results.Add((New-ControlResult 'vuln_certificates_vuln' @(1,2,3) `
    'Certificats cryptographiquement vulnérables' `
    $(if ($certBad.Count) {'Failed'} else {'Passed'}) @($certBad) `
    'Remplacer les certificats DSA, ROCA, faibles ou indécodables par des certificats conformes.' `
    'Attributs de certificats (objets ORADAD)' 'Implemented' $certificateFailedLevels))

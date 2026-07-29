param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_kerberos_properties_encryption'
        Levels = [int[]]@(3)
        Title = 'Algorithmes de chiffrement supportés par les comptes de service'
    }
}

# Le contrôle ANSSI vise ici les comptes de service non-machine. Les comptes
# machine Windows négocient et mettent eux-mêmes à jour leurs capacités.
$weakKerberos = @($users | Where-Object {
    $_.servicePrincipalName -and -not (Test-UacFlag $_ 2) -and
    ((-not $_.'msDS-SupportedEncryptionTypes') -or
     $_.'msDS-SupportedEncryptionTypes' -match '(?i)DES' -or
     $_.'msDS-SupportedEncryptionTypes' -notmatch '(?i)AES')
} | Select-Object dn,sAMAccountName,'msDS-SupportedEncryptionTypes')
Add-RemainingControl 'vuln_kerberos_properties_encryption' @(3) `
    'Algorithmes de chiffrement supportés par les comptes de service Kerberos' $weakKerberos `
    'Pour les comptes de service non-machine, activer explicitement AES128/AES256 ; utiliser 0x1C si la compatibilité RC4 reste nécessaire.' `
    "$prefix\user.tsv"

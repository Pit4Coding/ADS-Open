param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_kerberos_properties_deskey'
        Levels = [int[]]@(2)
        Title = 'Comptes utilisateurs avec un chiffrement Kerberos faible'
    }
}

$des = @($users | Where-Object {
    -not (Test-UacFlag $_ 2) -and ((Test-UacFlag $_ 2097152) -or $_.'msDS-SupportedEncryptionTypes' -match 'DES')
} | Select-Object dn, sAMAccountName, 'msDS-SupportedEncryptionTypes')
$results.Add((New-ControlResult 'vuln_kerberos_properties_deskey' @(2) 'Comptes utilisateurs avec un chiffrement Kerberos faible' `
    $(if ($des.Count) { 'Failed' } else { 'Passed' }) $des `
    'Supprimer DES et imposer AES pour les comptes compatibles.' "$prefix\user.tsv"))

param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_compatible_2000_not_default'
        Levels = [int[]]@(3)
        Title = 'Comptes ou groupes membres de "Pre-Windows 2000 Compatible Access"'
    }
}

$compat = @($groups | Where-Object { (Get-PrincipalRid $_) -eq '554' } | Where-Object {
    Split-MultiValue $_.member | Where-Object { $_ -notmatch 'S-1-5-11|Authenticated Users' }
} | Select-Object dn,member)
Add-RemainingControl 'vuln_compatible_2000_not_default' @(3) `
    'Accès compatible pré-Windows 2000 non conforme' $compat `
    'Rétablir la composition par défaut du groupe.' "$prefix\group.tsv"

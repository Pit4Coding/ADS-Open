param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_compatible_2000_anonymous'
        Levels = [int[]]@(2)
        Title = 'Le groupe "Pre-Windows 2000 Compatible Access" contient "Anonymous"'
    }
}

$anonymous = @($groups | Where-Object {
    (Get-PrincipalRid $_) -eq '554' -and $_.member -match 'S-1-5-7'
} | Select-Object dn, member)
$results.Add((New-ControlResult 'vuln_compatible_2000_anonymous' @(2) 'Pre-Windows 2000 Compatible Access contient Anonymous' `
    $(if ($anonymous.Count) { 'Failed' } else { 'Passed' }) $anonymous `
    'Retirer Anonymous du groupe Pre-Windows 2000 Compatible Access.' "$prefix\group.tsv"))

param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_protected_users'
        Levels = [int[]]@(3)
        Title = 'Comptes privilégiés non membres du groupe Protected Users'
    }
}

$protectedUsers = @($groups | Where-Object { (Get-PrincipalRid $_) -eq '525' } | ForEach-Object {
    @([string]$_.member -split ';' | Where-Object { $_ })
})
# Le compte Administrateur intégré (RID 500), conservé comme compte de
# secours, est explicitement exclu de ce contrôle ANSSI.
$notProtected = @($privilegedAccounts | Where-Object {
    (Get-PrincipalRid $_) -ne '500' -and $_.dn -notin $protectedUsers
} |
    Select-Object dn, sAMAccountName)
$results.Add((New-ControlResult 'vuln_protected_users' @(3) 'Comptes privilégiés non membres du groupe Protected Users' `
    $(if ($notProtected.Count) { 'Failed' } else { 'Passed' }) $notProtected `
    'Ajouter les comptes privilégiés compatibles au groupe Protected Users après validation des impacts.' "$prefix\user.tsv; $prefix\group.tsv"))

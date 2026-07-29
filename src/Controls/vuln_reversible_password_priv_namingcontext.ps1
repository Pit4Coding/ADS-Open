param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_reversible_password_priv_namingcontext'
        Levels = [int[]]@(3)
        Title = '[BETA] Mots de passe stockés en clair à cause d''un attribut à la racine du naming context'
    }
}

$reversible = @($roots | Where-Object { ((Get-Integer $_.pwdProperties) -band 16) -ne 0 } |
    Select-Object dn,pwdProperties)
Add-RemainingControl 'vuln_reversible_password_priv_namingcontext' @(3) `
    'Stockage réversible des mots de passe autorisé sur le domaine' $reversible `
    'Désactiver le stockage réversible des mots de passe.' "$prefix\root.tsv"

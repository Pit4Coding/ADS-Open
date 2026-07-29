param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_adcs_control'; Levels=[int[]]@(1); Title='Permissions dangereuses sur les conteneurs de certificats (chemins de contrôle)' }
}
Add-AclControl 'vuln_adcs_control' @(1) `
        'Permissions dangereuses sur les conteneurs de certificats (chemins de contrôle)' `
        @($caPublicationRelations | Where-Object TargetDn -match 'CN=(Certification Authorities|AIA|CDP|NTAuthCertificates),CN=Public Key Services' |
            Where-Object SourceDn -notlike 'CN=Cert Publishers,*' |
            Select-Object $relationFields) `
        'Restaurer les permissions par défaut sur les conteneurs de certificats.'
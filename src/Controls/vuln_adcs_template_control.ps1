param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_adcs_template_control'; Levels=[int[]]@(1,2); Title='Permissions dangereuses sur les objets de modèles de certificats (chemins de contrôle)' }
}
Add-AclControl 'vuln_adcs_template_control' @(1,2) `
        'Permissions dangereuses sur les objets de modèles de certificats (chemins de contrôle)' `
        @($actionableAclRelations | Where-Object TargetDn -match ',CN=Certificate Templates,CN=Public Key Services' |
            Where-Object Right -notin @(
                'ExtendedRight:CertificateEnrollment',
                'ExtendedRight:CertificateAutoEnrollment'
            ) |
            Select-Object $relationFields) `
        'Retirer les permissions dangereuses sur les objets de modèles de certificats.'
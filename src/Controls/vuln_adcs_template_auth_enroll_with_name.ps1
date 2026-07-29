param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_adcs_template_auth_enroll_with_name'; Levels=[int[]]@(1); Title='Permissions d''enrôlement dangereuses sur des modèles de certificats permettant l''authentification' }
}
Add-AclControl 'vuln_adcs_template_auth_enroll_with_name' @(1) `
        "Permissions d'enrôlement dangereuses sur des modèles de certificats permettant l'authentification" `
        @($actionableAclRelations | Where-Object {
            $_.TargetDn -in $vulnerableTemplateDns -and
            $_.Right -in @('ExtendedRight:CertificateEnrollment','ExtendedRight:CertificateAutoEnrollment','AllExtendedRights','GenericAll')
        } | Select-Object $relationFields) `
        "Interdire au demandeur de fournir un sujet arbitraire ou limiter strictement les droits d'enrôlement."
$modulePath = Join-Path $PSScriptRoot '..\src\ADSOpen.psm1'
$module = Import-Module $modulePath -Force -PassThru

Describe 'vuln_privileged_members - comptes de service' {
    It 'classe au niveau 1 un gMSA imbriqué dans Administrators' {
        $groups = @(
            [pscustomobject]@{ dn='CN=Administrators,CN=Builtin,DC=test,DC=org'; objectSid='S-1-5-32-544'; member='CN=Nested,DC=test,DC=org' },
            [pscustomobject]@{ dn='CN=Nested,DC=test,DC=org'; objectSid='S-1-5-21-1-1200'; member='CN=svc,CN=Managed Service Accounts,DC=test,DC=org' }
        )
        $gmsa = @([pscustomobject]@{ dn='CN=svc,CN=Managed Service Accounts,DC=test,DC=org'; objectSid='S-1-5-21-1-1300'; sAMAccountName='svc$' })
        $findings = & $module { param($groups,$gmsa) Get-ADSOpenPrivilegedServiceMemberships -Groups $groups -Users @() -Smsa @() -Gmsa $gmsa } $groups $gmsa
        $findings.Count | Should Be 1
        $findings[0].Level | Should Be 1
        $findings[0].AccountType | Should Be 'gMSA'
        $findings[0].Membership | Should Be 'Indirect'
    }
    It 'classe au niveau 1 un compte utilisateur de service direct dans Domain Admins' {
        $groups = @([pscustomobject]@{ dn='CN=Domain Admins,DC=test,DC=org'; objectSid='S-1-5-21-1-512'; member='CN=svc-user,DC=test,DC=org' })
        $users = @([pscustomobject]@{ dn='CN=svc-user,DC=test,DC=org'; objectSid='S-1-5-21-1-1400'; sAMAccountName='svc-user'; servicePrincipalName='HTTP/app.test.org'; userAccountControl_int='512' })
        $findings = & $module { param($groups,$users) Get-ADSOpenPrivilegedServiceMemberships -Groups $groups -Users $users -Smsa @() -Gmsa @() } $groups $users
        $findings.Count | Should Be 1
        $findings[0].Level | Should Be 1
        $findings[0].AccountType | Should Be 'Compte utilisateur de service (SPN)'
        $findings[0].Membership | Should Be 'Direct'
    }
}
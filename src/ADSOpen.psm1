Set-StrictMode -Version 2.0

$script:ADSOpenVersion = '1.3.2'

. (Join-Path $PSScriptRoot 'ControlLoader.ps1')

$script:AnssiControlGuidance = @{}
$guidancePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'data\anssi-control-guidance.json'
if (-not (Test-Path -LiteralPath $guidancePath)) {
    throw "Catalogue ANSSI hors ligne introuvable : $guidancePath. Le rapport ne peut pas être généré sans ses fiches détaillées."
}
foreach ($guidance in @(Get-Content -Raw -LiteralPath $guidancePath | ConvertFrom-Json)) {
    if ($guidance.Id -and $guidance.Description -and $guidance.Recommendation -and $guidance.ReviewedOn) {
        $script:AnssiControlGuidance[[string]$guidance.Id] = $guidance
    }
}
if ($script:AnssiControlGuidance.Count -ne 76) {
    throw "Catalogue ANSSI hors ligne incomplet : $($script:AnssiControlGuidance.Count)/76 fiches complètes. Rapport interrompu pour éviter des descriptions vides."
}

function Resolve-OradadRoot {
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (Test-Path -LiteralPath (Join-Path $resolved 'tables.tsv')) { return $resolved }

    $candidates = @(Get-ChildItem -LiteralPath $resolved -Filter tables.tsv -File -Recurse |
        Sort-Object FullName -Descending)
    if ($candidates.Count -eq 0) {
        throw "Aucun fichier tables.tsv ORADAD trouvé sous '$resolved'."
    }
    return $candidates[0].Directory.FullName
}

function New-OradadDataset {
    param([Parameter(Mandatory)][string]$Root)

    $schemas = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $Root 'tables.tsv')) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split "`t", 0, 'SimpleMatch'
        if ($parts.Count -lt 4) { continue }
        $count = 0
        if (-not [int]::TryParse($parts[3], [ref]$count)) { continue }
        $columns = for ($i = 0; $i -lt $count; $i++) { $parts[4 + (2 * $i)] }
        $key = $parts[0].Replace('/', '\')
        $schemas[$key] = [pscustomobject]@{ Path = $key; Columns = [string[]]$columns }
    }

    [pscustomobject]@{
        Root    = $Root
        Schemas = $schemas
        Cache   = @{}
    }
}

function Get-OradadRows {
    param(
        [Parameter(Mandatory)]$Dataset,
        [Parameter(Mandatory)][string]$RelativePath
    )

    $key = $RelativePath.Replace('/', '\')
    if ($Dataset.Cache.ContainsKey($key)) { return @($Dataset.Cache[$key]) }
    if (-not $Dataset.Schemas.ContainsKey($key)) {
        $Dataset.Cache[$key] = @()
        return @()
    }

    $file = Join-Path $Dataset.Root $key
    if (-not (Test-Path -LiteralPath $file)) {
        $Dataset.Cache[$key] = @()
        return @()
    }

    $rows = @(Import-Csv -LiteralPath $file -Delimiter "`t" -Header $Dataset.Schemas[$key].Columns)
    $Dataset.Cache[$key] = $rows
    return $rows
}

function Test-UacFlag {
    param($Object, [int64]$Flag)
    $value = 0L
    return [int64]::TryParse([string]$Object.userAccountControl_int, [ref]$value) -and (($value -band $Flag) -ne 0)
}

function Test-ForestTrustSidHistoryEnabled {
    param([Parameter(Mandatory)]$Trust)

    $attributes = 0L
    $direction = 0L
    if (-not [int64]::TryParse([string]$Trust.trustAttributes_int, [ref]$attributes)) { return $false }
    if (-not [int64]::TryParse([string]$Trust.trustDirection_int, [ref]$direction)) { return $false }

    return (($direction -band 0x2) -ne 0) -and `
        (($attributes -band 0x8) -ne 0) -and `
        (($attributes -band 0x40) -ne 0)
}

function Test-ADSOpenTrustedCertificateContainer {
    param([string]$DistinguishedName)

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $false }
    return $DistinguishedName -match '(?i)^CN=NTAuthCertificates,CN=Public Key Services,' -or
        $DistinguishedName -match '(?i),CN=(Certification Authorities|AIA),CN=Public Key Services,'
}

function Test-ADSOpenCertificateInScope {
    param(
        [Parameter(Mandatory)]$Certificate,
        [string]$HolderDn,
        [datetime]$ReferenceTime = (Get-Date)
    )

    if ($Certificate.NotAfter.ToUniversalTime() -ge $ReferenceTime.ToUniversalTime()) { return $true }
    return Test-ADSOpenTrustedCertificateContainer $HolderDn
}

function Convert-OradadDate {
    param([string]$Value)
    $date = [datetime]::MinValue
    if ([datetime]::TryParse($Value, [ref]$date)) { return $date }
    return $null
}

function Get-OradadValue {
    param($Object,[string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-PrincipalRid {
    param($Object)
    $rid = [string](Get-OradadValue $Object 'rid')
    if ($rid) { return $rid }
    $sid = [string](Get-OradadValue $Object 'objectSid')
    if (-not $sid) { $sid = [string](Get-OradadValue $Object 'securityIdentifier') }
    if ($sid -match '-(\d+)$') { return $Matches[1] }
    return ''
}

function Get-ADSOpenPrivilegedServiceMemberships {
    param([object[]]$Groups,[object[]]$Users,[object[]]$Smsa,[object[]]$Gmsa)

    $groupByDn = @{}
    foreach ($group in @($Groups)) { if ($group.dn) { $groupByDn[[string]$group.dn] = $group } }
    $serviceByDn = @{}
    foreach ($account in @($Users | Where-Object { $_.servicePrincipalName -and -not (Test-UacFlag $_ 2) })) {
        if ($account.dn) { $serviceByDn[[string]$account.dn] = [pscustomobject]@{ Account=$account; Type='Compte utilisateur de service (SPN)' } }
    }
    foreach ($account in @($Smsa)) {
        if ($account.dn) { $serviceByDn[[string]$account.dn] = [pscustomobject]@{ Account=$account; Type='sMSA' } }
    }
    foreach ($account in @($Gmsa)) {
        if ($account.dn) { $serviceByDn[[string]$account.dn] = [pscustomobject]@{ Account=$account; Type='gMSA' } }
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $findingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rootGroup in @($Groups | Where-Object { (Get-PrincipalRid $_) -in @('512','544') })) {
        $pending = [System.Collections.Generic.Queue[object]]::new()
        $pending.Enqueue([pscustomobject]@{ Dn=[string]$rootGroup.dn; Depth=0 })
        $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        while ($pending.Count -gt 0) {
            $current = $pending.Dequeue()
            if (-not $visited.Add($current.Dn)) { continue }
            $currentGroup = $groupByDn[$current.Dn]
            if (-not $currentGroup) { continue }
            foreach ($memberDn in @([string]$currentGroup.member -split ';' | Where-Object { $_ })) {
                if ($groupByDn.ContainsKey($memberDn)) {
                    $pending.Enqueue([pscustomobject]@{ Dn=$memberDn; Depth=$current.Depth + 1 })
                } elseif ($serviceByDn.ContainsKey($memberDn)) {
                    if (-not $findingKeys.Add(('{0}|{1}' -f $rootGroup.dn,$memberDn))) { continue }
                    $service = $serviceByDn[$memberDn]
                    $findings.Add([pscustomobject]@{
                        Level=1; dn=$memberDn; sAMAccountName=[string]$service.Account.sAMAccountName
                        AccountType=$service.Type; PrivilegedGroupDn=[string]$rootGroup.dn
                        Membership=$(if ($current.Depth -eq 0) { 'Direct' } else { 'Indirect' })
                    })
                }
            }
        }
    }
    return @($findings)
}
function New-ControlResult {
    param(
        [string]$Id,
        [int[]]$Levels,
        [string]$Title,
        [string]$Status,
        [object[]]$Findings,
        [string]$Recommendation,
        [string]$DataSource,
        [string]$Implementation = 'Implemented',
        [int[]]$FailedLevels
    )
    if ($null -eq $FailedLevels) {
        $FailedLevels = if ($Status -eq 'Failed') { $Levels } else { @() }
    }
    $guidance = $script:AnssiControlGuidance[$Id]
    [pscustomobject]@{
        Id             = $Id
        Type           = 'Vulnerability'
        AffectsScore   = $true
        Levels         = $Levels
        FailedLevels   = @($FailedLevels)
        Title          = $Title
        Status         = $Status
        FindingCount   = ($Findings | Measure-Object).Count
        Findings       = @($Findings)
        Recommendation = $Recommendation
        DetailedDescription = if ($guidance) { [string]$guidance.Description } else { '' }
        OfficialRecommendation = if ($guidance) { [string]$guidance.Recommendation } else { '' }
        GuidanceReviewedOn = if ($guidance) { [string]$guidance.ReviewedOn } else { '' }
        DataSource     = $DataSource
        Implementation = $Implementation
        Reference      = "https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#$Id"
    }
}

function Get-ADSOpenAnalysis {
    param([Parameter(Mandatory)]$Dataset)

    $domain = Split-Path (Split-Path $Dataset.Root -Parent) -Leaf
    if (-not $domain -or $domain -notmatch '\.') {
        $domainDir = Get-ChildItem -LiteralPath (Join-Path $Dataset.Root 'domain') -Directory |
            Select-Object -First 1
        $domain = $domainDir.Name
    }
    $prefix = "domain\$domain"
    $users = @(Get-OradadRows $Dataset "$prefix\user.tsv")
    $computers = @(Get-OradadRows $Dataset "$prefix\computer.tsv")
    $groups = @(Get-OradadRows $Dataset "$prefix\group.tsv")
    $roots = @(Get-OradadRows $Dataset "$prefix\root.tsv")
    $trusts = @(Get-OradadRows $Dataset "$prefix\trustedDomain.tsv")
    $ntfrs = @(Get-OradadRows $Dataset "$prefix\nTFRSReplicaSet.tsv")
    $smsa = @(Get-OradadRows $Dataset "$prefix\smsa.tsv")
    $gmsa = @(Get-OradadRows $Dataset "$prefix\gmsa.tsv")
    $foreign = @(Get-OradadRows $Dataset "$prefix\foreignSecurityPrincipal.tsv")
    $ous = @(Get-OradadRows $Dataset "$prefix\ou.tsv")
    $gpos = @(Get-OradadRows $Dataset "$prefix\gpo.tsv")
    $certificateTemplates = @(Get-OradadRows $Dataset 'configuration\pKICertificateTemplate.tsv')
    $enrollmentServices = @(Get-OradadRows $Dataset 'configuration\pKIEnrollmentService.tsv')
    $certificationAuthorities = @(Get-OradadRows $Dataset 'configuration\certificationauthority.tsv')
    $crossRefs = @(Get-OradadRows $Dataset 'configuration\crossRef.tsv')
    $ntdsServices = @(Get-OradadRows $Dataset 'configuration\nTDSService.tsv')
    $servers = @(Get-OradadRows $Dataset 'configuration\server.tsv')
    $ntdsDsas = @(Get-OradadRows $Dataset 'configuration\nTDSDSA.tsv')
    $displaySpecifiers = @(Get-OradadRows $Dataset 'configuration\displaySpecifier.tsv')
    $authPolicySilos = @(Get-OradadRows $Dataset 'configuration\authNPolicySilo.tsv')
    $passwordSettings = @(Get-OradadRows $Dataset "$prefix\passwordSettings.tsv")
    $dnsZones = @(
        Get-OradadRows $Dataset "$prefix\dnsZone.tsv"
        Get-OradadRows $Dataset "domaindns\$domain\dnsZone.tsv"
        Get-OradadRows $Dataset 'forestdns\dnsZone.tsv'
    )
    $now = Get-Date
    $results = [System.Collections.Generic.List[object]]::new()

    # Les groupes privilégiés retenus par le contrôle public ANSSI sont résolus
    # récursivement. Les RID intégrés évitent toute dépendance à la langue du domaine.
    $privilegedGroupRids = @('512','516','518','519','526','527','544','548','549','550','551','552')
    $privilegedGroups = @($groups | Where-Object { (Get-PrincipalRid $_) -in $privilegedGroupRids })
    $groupByDn = @{}
    foreach ($group in $groups) { $groupByDn[$group.dn.ToLowerInvariant()] = $group }
    $privilegedDns = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Queue[string]]::new()
    foreach ($group in $privilegedGroups) { $pending.Enqueue($group.dn) }
    while ($pending.Count -gt 0) {
        $groupDn = $pending.Dequeue()
        if (-not $privilegedDns.Add($groupDn)) { continue }
        $group = $groupByDn[$groupDn.ToLowerInvariant()]
        if (-not $group) { continue }
        foreach ($memberDn in @([string]$group.member -split ';' | Where-Object { $_ })) {
            if ($groupByDn.ContainsKey($memberDn.ToLowerInvariant())) { $pending.Enqueue($memberDn) }
            else { [void]$privilegedDns.Add($memberDn) }
        }
    }
    $privilegedAccounts = @($users + $computers | Where-Object {
        ($privilegedDns.Contains($_.dn) -or $_.objectSid -match '-500$') -and
        $_.primaryGroupID -notin @('516','521')
    })
    $privilegedAccountsForCount = @($privilegedAccounts | Where-Object objectSid -notmatch '-500$')
    $privilegedServiceMemberships = @(Get-ADSOpenPrivilegedServiceMemberships -Groups $groups -Users $users -Smsa $smsa -Gmsa $gmsa)

    . (Join-Path $PSScriptRoot 'Controls\vuln_guest.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_dont_expire.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_dont_expire_priv.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_kerberos_properties_preauth.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_kerberos_properties_preauth_priv.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_spn_priv.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_kerberos_properties_deskey.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_reversible_password_priv_uac.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_sidhistory_present.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_primary_group_id_1000.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_delegation_t4d.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_delegation_sourcedeleg.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_krbtgt.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_dc_no_change.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_dc_obsolete.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_dc_inconsistent_uac.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_inactive_dc.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_priv.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_privileged_members_no_admincount.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_protected_users.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_silo_priv.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_server_no_change_45.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_server_no_change_90.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_inactive_servers.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_msa_no_change_90.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_primary_group_id_nochange.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_smartcard_expire_passwords.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_user_accounts_machineaccountquota.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_compatible_2000_anonymous.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_sysvol_ntfrs.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_trusts_domain_notfiltered.ps1') -Mode Evaluate

    # Analyse des descripteurs de sécurité et des chemins de contrôle.
    Import-Module (Join-Path $PSScriptRoot 'ACLGraph.psm1') -Force
    $topPaths = @(
        "$prefix\top.tsv",
        'configuration\top.tsv',
        'schema\top.tsv',
        'forestdns\top.tsv',
        "domaindns\$domain\top.tsv"
    )
    $allObjects = @($topPaths | ForEach-Object { Get-OradadRows $Dataset $_ })
    $attributes = @(Get-OradadRows $Dataset 'schema\attribute.tsv')
    $domainSid = [string](($users | Where-Object objectSid -match '-500$' | Select-Object -First 1).objectSid)
    $domainSid = $domainSid -replace '-500$', ''
    $domainDn = ($roots | Select-Object -First 1).dn
    $configurationDn = "CN=Configuration,$domainDn"
    $schemaDn = "CN=Schema,$configurationDn"
    $dcDns = @($computers | Where-Object { $_.primaryGroupID -in @('516','521') } | ForEach-Object dn)
    $tier0Dns = @(
        $domainDn, $configurationDn, $schemaDn,
        ($users | Where-Object objectSid -match '-(500|502)$' | ForEach-Object dn),
        ($groups | Where-Object { (Get-PrincipalRid $_) -in $privilegedGroupRids } | ForEach-Object dn),
        $dcDns,
        "CN=AdminSDHolder,CN=System,$domainDn"
    ) | Where-Object { $_ } | Select-Object -Unique
    $acl = Get-ADSOpenAclAnalysis -Objects $allObjects `
        -Principals @($users + $computers + $groups + $foreign + $smsa + $gmsa) `
        -Groups $groups -Attributes $attributes -DomainSid $domainSid -Tier0Dns $tier0Dns

    $objectByDn = @{}
    foreach ($object in $allObjects) {
        if ($object.dn) { $objectByDn[$object.dn.ToLowerInvariant()] = $object }
    }
    $adminSdHolderDn = "CN=AdminSDHolder,CN=System,$domainDn"
    $adminSdHolderObject = $objectByDn[$adminSdHolderDn.ToLowerInvariant()]
    $adminSdHolderProtectedDns = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    if ($adminSdHolderObject) {
        foreach ($account in $privilegedAccounts) {
            $key = ([string]$account.dn).ToLowerInvariant()
            if ($objectByDn.ContainsKey($key) -and
                (Test-ADSOpenAdminSdHolderProtection -Object $objectByDn[$key] `
                    -AdminSdHolder $adminSdHolderObject)) {
                [void]$adminSdHolderProtectedDns.Add([string]$account.dn)
            }
        }
    }
    # Les groupes opératifs intégrés sont volontairement inutilisés lorsqu'ils
    # sont vides. Leur ACE native ne constitue alors pas un chemin exploitable.
    # Dès qu'un membre direct ou imbriqué existe, leurs relations sont conservées.
    $populatedGroupDns = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($group in $groups) {
        foreach ($memberDn in @([string]$group.member -split ';' | Where-Object { $_ })) {
            if (-not $groupByDn.ContainsKey($memberDn.ToLowerInvariant())) {
                [void]$populatedGroupDns.Add($group.dn)
            }
        }
    }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($group in $groups) {
            if ($populatedGroupDns.Contains($group.dn)) { continue }
            foreach ($memberDn in @([string]$group.member -split ';' | Where-Object { $_ })) {
                if ($populatedGroupDns.Contains($memberDn)) {
                    if ($populatedGroupDns.Add($group.dn)) { $changed = $true }
                    break
                }
            }
        }
    }
    $operationalGroupRids = @('548','549','550','551','552')
    $unusedOperationalDns = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($group in $groups | Where-Object {
        (Get-PrincipalRid $_) -in $operationalGroupRids -or $_.sAMAccountName -eq 'DnsAdmins'
    }) {
        if (-not $populatedGroupDns.Contains($group.dn)) { [void]$unusedOperationalDns.Add($group.dn) }
    }
    $trustedAclSourceDns = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dn in @($privilegedDns) + @($dcDns)) {
        if ($dn) { [void]$trustedAclSourceDns.Add($dn) }
    }
    $actionableAclRelations = @($acl.Relations | Where-Object {
        $sourceIsTrusted = $_.SourceDn -and $trustedAclSourceDns.Contains($_.SourceDn)
        $sourceIsUnusedOperator = $_.SourceDn -and $unusedOperationalDns.Contains($_.SourceDn)
        $isRodcReplicationRight = $_.Right -in @(
            'ExtendedRight:DCSyncGetChanges',
            'ExtendedRight:DCSyncGetChangesAll',
            'ExtendedRight:DCSyncFilteredSet'
        )
        $isExpectedRodcReplication = $_.SourceSid -eq "$domainSid-498" -and
            $isRodcReplicationRight -and
            ($_.Right -eq 'ExtendedRight:DCSyncGetChanges' -or $_.TargetDn -ne $domainDn)
        $isExpectedPasswordChange = $_.SourceSid -in @('S-1-1-0','S-1-5-10') -and
            $_.Right -eq 'ExtendedRight:ChangePassword'
        -not ($sourceIsTrusted -or $sourceIsUnusedOperator -or
            $isExpectedRodcReplication -or $isExpectedPasswordChange)
    })

    function Add-AclControl {
        param([string]$Id, [int[]]$Levels, [string]$Title, [object[]]$Findings, [string]$Recommendation)
        # Group-Object conserve une copie logique de chaque groupe et peut doubler
        # le pic mémoire. Cette agrégation incrémentale produit le même constat.
        $buckets = [ordered]@{}
        foreach ($finding in $Findings) {
            $key = @(
                [string]$finding.SourceSid, [string]$finding.SourceDn,
                [string]$finding.TargetDn, [string]$finding.Inherited,
                [string]$finding.AccessMask, [string]$finding.ObjectType
            ) -join [char]31
            if (-not $buckets.Contains($key)) {
                $buckets[$key] = [pscustomobject]@{
                    First = $finding
                    Rights = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                }
            }
            [void]$buckets[$key].Rights.Add([string]$finding.Right)
        }
        $compressed = @($buckets.Values | ForEach-Object {
            $first = $_.First
            [pscustomobject]@{
                SourceSid=$first.SourceSid
                SourceDn=$first.SourceDn
                TargetDn=$first.TargetDn
                Right=(@($_.Rights) | Sort-Object) -join ', '
                Inherited=$first.Inherited
                AccessMask=$first.AccessMask
                ObjectType=$first.ObjectType
            }
        })
        $results.Add((New-ControlResult $Id $Levels $Title `
            $(if (($compressed | Measure-Object).Count) { 'Failed' } else { 'Passed' }) $compressed `
            $Recommendation 'nTSecurityDescriptor (partitions ORADAD)' 'Implemented'))
    }
    $relationFields = 'SourceSid','SourceDn','TargetDn','Right','Inherited','AccessMask','ObjectType'
    # Le service de certificats publie légitimement le certificat de sa propre CA
    # dans AIA et ses listes de révocation dans son point CDP. L'exception est
    # volontairement bornée au compte machine indiqué par dNSHostName, à la CA
    # correspondante et à ces deux objets de publication seulement.
    $computerByHost = @{}
    foreach ($computer in $computers) {
        if ($computer.dNSHostName) { $computerByHost[[string]$computer.dNSHostName] = $computer }
        if ($computer.sAMAccountName) { $computerByHost[([string]$computer.sAMAccountName).TrimEnd('$')] = $computer }
    }
    $caPublicationExceptions = [System.Collections.Generic.List[object]]::new()
    foreach ($service in $enrollmentServices) {
        $caName = ([string]$service.dn -split ',', 2)[0] -replace '^(?i)CN=', ''
        $caHost = ([string]$service.dNSHostName -split '\.', 2)[0]
        $hostComputer = $computerByHost[[string]$service.dNSHostName]
        if (-not $hostComputer) { $hostComputer = $computerByHost[$caHost] }
        if ($hostComputer) {
            $caPublicationExceptions.Add([pscustomobject]@{
                SourceDn = [string]$hostComputer.dn
                AiaPrefix = "CN=$caName,CN=AIA,CN=Public Key Services,"
                CdpPrefix = "CN=$caName,CN=$caHost,CN=CDP,CN=Public Key Services,"
            })
        }
    }
    $caPublicationRelations = @($actionableAclRelations | Where-Object {
        $relation = $_
        $isExpectedCaPublication = $false
        foreach ($exception in $caPublicationExceptions) {
            if (-not ([string]$relation.SourceDn).Equals([string]$exception.SourceDn,
                    [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            if ([string]$relation.TargetDn.StartsWith($exception.AiaPrefix,
                    [System.StringComparison]::OrdinalIgnoreCase) -or
                [string]$relation.TargetDn.StartsWith($exception.CdpPrefix,
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                $isExpectedCaPublication = $true
                break
            }
        }
        -not $isExpectedCaPublication
    })
    . (Join-Path $PSScriptRoot 'Controls\vuln_adcs_control.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_adcs_template_control.ps1') -Mode Evaluate
    $publishedTemplates = @($enrollmentServices | ForEach-Object {
        @([string]$_.certificateTemplates -split ';' | Where-Object { $_ })
    })
    $vulnerableTemplateDns = @($certificateTemplates | Where-Object {
        $nameFlag = 0L
        $enrollmentFlag = 0L
        $raSignatures = 0L
        [int64]::TryParse([string]$_.'msPKI-Certificate-Name-Flag', [ref]$nameFlag) -and
        [int64]::TryParse([string]$_.'msPKI-Enrollment-Flag', [ref]$enrollmentFlag) -and
        [int64]::TryParse([string]$_.'msPKI-RA-Signature', [ref]$raSignatures) -and
        (($nameFlag -band 1) -ne 0) -and
        (($enrollmentFlag -band 2) -eq 0) -and
        ($raSignatures -eq 0) -and
        ((-not $_.pKIExtendedKeyUsage) -or
         $_.pKIExtendedKeyUsage -match '1\.3\.6\.1\.5\.5\.7\.3\.2|1\.3\.6\.1\.4\.1\.311\.20\.2\.2|1\.3\.6\.1\.5\.2\.3\.4|2\.5\.29\.37\.0') -and
        ($_.displayName -in $publishedTemplates -or (($_.dn -split ',')[0] -replace '^CN=', '') -in $publishedTemplates)
    } | ForEach-Object dn)
    . (Join-Path $PSScriptRoot 'Controls\vuln_adcs_template_auth_enroll_with_name.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_adminsdholder.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_dc.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_dfsr_sysvol.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_dpapi.ps1') -Mode Evaluate
    $gmsaDns = @($gmsa | ForEach-Object dn)
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_gmsa_keys.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_naming_context.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_schema.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_msdns.ps1') -Mode Evaluate
    # Selon l'acceptation du risque ANSSI, les comptes effectivement protégés
    # « à la adminSDHolder » sortent de ce contrôle. adminCount=1 ne suffit pas :
    # la DACL protégée est comparée à celle d'AdminSDHolder par le moteur ACL.
    $privilegedAccountDns = @($privilegedAccounts | Where-Object {
        -not $adminSdHolderProtectedDns.Contains($_.dn)
    } | ForEach-Object dn)
    . (Join-Path $PSScriptRoot 'Controls\vuln_privileged_members_perm.ps1') -Mode Evaluate
    $dnsAdmins = @($groups | Where-Object sAMAccountName -eq 'DnsAdmins')
    $dnsAdminFindings = @(
        $actionableAclRelations | Where-Object TargetDn -in @($dnsAdmins | ForEach-Object dn) | Select-Object $relationFields
        $dnsAdmins | Where-Object member | ForEach-Object {
            [pscustomobject]@{ SourceSid=''; SourceDn=$_.member; TargetDn=$_.dn; Right='Member'; Inherited=$false }
        }
    )
    . (Join-Path $PSScriptRoot 'Controls\vuln_dnsadmins.ps1') -Mode Evaluate
    $standardOwnerSids = @(
        'S-1-5-18','S-1-5-32-544',"$domainSid-512","$domainSid-519"
    )
    $ownerTargetClasses = @(
        'user','group','computer','organizationalUnit','groupPolicyContainer',
        'msDS-ManagedServiceAccount','msDS-GroupManagedServiceAccount'
    )
    $badOwners = @($acl.Relations | Where-Object Right -eq 'Owner' | Where-Object {
        if ($_.SourceSid -in $standardOwnerSids) { return $false }
        $key = ([string]$_.TargetDn).ToLowerInvariant()
        if (-not $objectByDn.ContainsKey($key)) { return $false }
        $target = $objectByDn[$key]
        if ($target.dn -like '*,CN=Deleted Objects,*') { return $false }
        $classes = @([string]$target.objectClass -split ';' | Where-Object { $_ })
        if (($classes | Where-Object { $_ -in $ownerTargetClasses } | Measure-Object).Count -eq 0) { return $false }
        $created = Convert-OradadDate ([string]$target.whenCreated)
        return $created -and $created -lt $now.AddDays(-7)
    } | Select-Object $relationFields)
    . (Join-Path $PSScriptRoot 'Controls\vuln_owner.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_gpo_priv.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_permissions_gpo_container_priv.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_critical_objects.ps1') -Mode Evaluate
    . (Join-Path $PSScriptRoot 'Controls\vuln_sd_failed_sd_read_on_priv.ps1') -Mode Evaluate

    # Contrôles complémentaires ne reposant pas sur les ACL.
    function Add-RemainingControl {
        param([string]$Id,[int[]]$Levels,[string]$Title,[object[]]$Findings,
            [string]$Recommendation,[string]$Source)
        $findingArray = @($Findings)
        $findingCount = ($Findings | Measure-Object).Count
        $status = if ($findingCount -gt 0) { 'Failed' } else { 'Passed' }
        $results.Add((New-ControlResult $Id $Levels $Title `
            $status $findingArray `
            $Recommendation $Source 'Implemented'))
    }
    function Split-MultiValue { param($Value) @([string]$Value -split ';' | Where-Object { $_ }) }
    function Get-Integer { param($Value) $n=0L; if ([int64]::TryParse([string]$Value,[ref]$n)){$n}else{0L} }

    $dcNames = @($computers | Where-Object primaryGroupID -in @('516','521') | ForEach-Object {
        $_.dNSHostName; ([string]$_.sAMAccountName).TrimEnd('$')
    } | Where-Object { $_ })
    $delegations = @($users + $computers | Where-Object {
        -not (Test-UacFlag $_ 2) -and $_.'msDS-AllowedToDelegateTo'
    } | ForEach-Object {
        $account = $_
        Split-MultiValue $_.'msDS-AllowedToDelegateTo' | Where-Object {
            $target = (($_ -split '/',2)[1] -split ':',2)[0]
            $target -in $dcNames -or $_ -match '(?i)/krbtgt([/:]|$)'
        } | ForEach-Object { [pscustomobject]@{ Dn=$account.dn; Service=$_ } }
    })
    . (Join-Path $PSScriptRoot 'Controls\vuln_delegation_a2d2.ps1') -Mode Evaluate
    $protocolTransition = @($delegations | Where-Object {
        $dn=$_.Dn; $a=@($users+$computers | Where-Object dn -eq $dn | Select-Object -First 1)
        $a.Count -and (Test-UacFlag $a[0] 16777216)
    })
    . (Join-Path $PSScriptRoot 'Controls\vuln_delegation_t2a4d.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_dsheuristics_bad.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_functional_level.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_privileged_members.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_user_accounts_dormant.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_dc_crypto.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_password_change_cluster_no_change_3years.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_privileged_members_password.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_sidhistory_dangerous.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_trusts_accounts.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_compatible_2000_not_default.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_kerberos_properties_encryption.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_reversible_password_priv_namingcontext.ps1') -Mode Evaluate

    $forestSidHistory = @($trusts | Where-Object {
        Test-ForestTrustSidHistoryEnabled $_
    } | Select-Object dn,trustPartner,trustDirection,trustAttributes,
        @{Name='EnableSIDHistory';Expression={'Yes'}})
    . (Join-Path $PSScriptRoot 'Controls\vuln_trusts_forest_sidhistory.ps1') -Mode Evaluate
    $tgtDeleg = @($trusts | Where-Object {
        $a=Get-Integer $_.trustAttributes_int; $d=Get-Integer $_.trustDirection_int
        (($d -band 1) -ne 0) -and (($a -band 2048) -ne 0)
    } | Select-Object dn,trustPartner,trustDirection,trustAttributes)
    . (Join-Path $PSScriptRoot 'Controls\vuln_trusts_tgt_deleg.ps1') -Mode Evaluate

    $rodcs = @($computers | Where-Object { $_.primaryGroupID -eq '521' -or $_.'msDS-isRODC' -eq '1' })
    $privTokens = @($privilegedDns) + @($privilegedGroupRids | ForEach-Object { "-$_" })
    $revealedPriv = @($rodcs | ForEach-Object {
        $r=$_
        Split-MultiValue $_.'msDS-RevealedUsers' | Where-Object {
            $x=$_; @($privTokens | Where-Object { $x -like "*$_*" }).Count
        } | ForEach-Object { [pscustomobject]@{RODC=$r.dn;Revealed=$_} }
    })
    . (Join-Path $PSScriptRoot 'Controls\vuln_rodc_priv_revealed.ps1') -Mode Evaluate
    $requiredNeverRids=@('512','518','519','544','548','549','551','552','572')
    $neverRevealBad=@($rodcs | Where-Object {
        $v=[string]$_.'msDS-NeverRevealGroup'
        @($requiredNeverRids | Where-Object { $v -notlike ('*-{0}*' -f $_) }).Count
    } | Select-Object dn,'msDS-NeverRevealGroup')
    . (Join-Path $PSScriptRoot 'Controls\vuln_rodc_never_reveal.ps1') -Mode Evaluate
    $revealBad=@($rodcs | Where-Object {
        [string]$_.'msDS-RevealOnDemandGroup' -match '-(5\d\d|[1-9]\d{0,2})([;,)]|$)'
    } | Select-Object dn,'msDS-RevealOnDemandGroup')
    . (Join-Path $PSScriptRoot 'Controls\vuln_rodc_reveal.ps1') -Mode Evaluate
    $allowed571=@($groups | Where-Object { (Get-PrincipalRid $_) -eq '571' } | Where-Object member | Select-Object dn,member)
    . (Join-Path $PSScriptRoot 'Controls\vuln_rodc_allowed_group.ps1') -Mode Evaluate
    $denied572=@($groups | Where-Object { (Get-PrincipalRid $_) -eq '572' })
    $requiredDeniedDns = @($groups | Where-Object {
        (Get-PrincipalRid $_) -in @('512','516','517','518','519','520','521')
    } | ForEach-Object dn)
    $requiredDeniedDns += @($users | Where-Object objectSid -match '-502$' | ForEach-Object dn)
    $deniedBad=if (-not $denied572.Count) {@([pscustomobject]@{Reason='Groupe RID 572 absent'})} else {
        @($denied572 | Where-Object {
            $members = @([string]$_.member -split ';' | Where-Object { $_ })
            ($requiredDeniedDns | Where-Object { $_ -notin $members } | Measure-Object).Count -gt 0
        } | Select-Object dn,member)
    }
    . (Join-Path $PSScriptRoot 'Controls\vuln_rodc_denied_group.ps1') -Mode Evaluate
    $linkedKrb=@($rodcs | ForEach-Object { $_.'msDS-KrbTgtLink' } | Where-Object { $_ })
    $orphanKrb=@($users | Where-Object {
        ($_.'msDS-SecondaryKrbTgtNumber' -or $_.sAMAccountName -match '^krbtgt_\d+$') -and
        $_.dn -notin $linkedKrb
    } | Select-Object dn,sAMAccountName,'msDS-SecondaryKrbTgtNumber')
    . (Join-Path $PSScriptRoot 'Controls\vuln_rodc_orphan_krbtgt.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_group_loop.ps1') -Mode Evaluate

    $displayBad=@($displaySpecifiers | Where-Object {
        $_.adminContextMenu -match '\\\\' -and $_.adminContextMenu -notmatch '(?i)\\SYSVOL\\'
    } | Select-Object dn,adminContextMenu)
    . (Join-Path $PSScriptRoot 'Controls\vuln_display_specifier.ps1') -Mode Evaluate
    $dnsBad=@($dnsZones | Where-Object {
        $_.dnsAllowDynamic -eq '1' -or $_.dnsAllowDynamic -match '(?i)UNSECURE'
    } | Select-Object dn,dc,dnsAllowDynamic,dNSProperty)
    . (Join-Path $PSScriptRoot 'Controls\vuln_dnszone_bad_prop.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_certificates_vuln.ps1') -Mode Evaluate

    . (Join-Path $PSScriptRoot 'Controls\vuln_adupdate_bad.ps1') -Mode Evaluate

    $implementedIds = @($results | ForEach-Object Id)
    $controlDefinitions = @(Get-ADSOpenControlDefinitions (Join-Path $PSScriptRoot 'Controls'))
    foreach ($item in $controlDefinitions) {
        if ($item.Id -in $implementedIds) { continue }
        $results.Add((New-ControlResult $item.Id $item.Levels $item.Title 'NotEvaluated' @() `
            "Contrôle intégré au catalogue officiel mais moteur d'évaluation non encore disponible pour les données nécessaires." `
            'Voir exigence ANSSI' 'Catalogued'))
    }
    $unknownIds = @($results | Where-Object Id -notin $controlDefinitions.Id | ForEach-Object Id)
    if ($unknownIds.Count) {
        throw "Résultats sans définition de contrôle : $($unknownIds -join ', ')"
    }

    $advisories = @(. (Join-Path $PSScriptRoot 'AdvisoryEngine.ps1'))
    return [pscustomobject]@{
        Controls   = @($results)
        Advisories = $advisories
    }
}

function Get-ADSOpenScore {
    param([object[]]$Controls)
    $failedLevels = @($Controls | Where-Object Status -eq 'Failed' |
        ForEach-Object {
            if ($_.PSObject.Properties['FailedLevels']) { $_.FailedLevels } else { $_.Levels }
        } | Sort-Object -Unique)
    $level = if ($failedLevels.Count) { [int]($failedLevels | Measure-Object -Minimum).Minimum } else { 5 }
    # Le barème exact du score ADS n'est pas public. Ce score ADS-Open cumule
    # les points des contrôles validés, avec une pondération plus forte pour
    # les mesures indispensables des premiers niveaux.
    $pointWeights = @{ 1=100; 2=40; 3=15; 4=5; 5=1 }
    $successPoints = 0
    foreach ($control in $Controls | Where-Object Status -eq 'Passed') {
        $controlLevels = @($control.Levels)
        $controlLevel = [int](($controlLevels | Measure-Object -Minimum).Minimum)
        $successPoints += $pointWeights[$controlLevel]
    }
    [pscustomobject]@{
        Level        = $level
        SuccessPoints = $successPoints
        SuccessPointsLabel = 'Score cumulé ADS-Open (estimation)'
        SuccessPointsMethod = 'Contrôles validés uniquement : N1=100, N2=40, N3=15, N4=5 et N5=1 point. Failed et NotEvaluated=0.'
        Passed       = @($Controls | Where-Object Status -eq 'Passed').Count
        Failed       = @($Controls | Where-Object Status -eq 'Failed').Count
        NotEvaluated = @($Controls | Where-Object Status -eq 'NotEvaluated').Count
    }
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][object]$Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-AnssiGuidanceHtml {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $normalized = $Text -replace "`r`n?", "`n"
    $blocks = @($normalized -split "`n\s*`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $markup = foreach ($block in $blocks) {
        $plain = $block.Trim()
        $encoded = (ConvertTo-HtmlEncoded $plain) -replace "`n", '<br>'
        $class = if ($plain -match '^(?i)(note|attention|limite|acceptation|exception|seuil(?:s)?(?: de tolérance)?|contexte)\s*:') {
            'anssi-callout'
        } elseif ($plain.Length -le 140 -and $plain -notmatch '[.!?;:]$') {
            'anssi-subheading'
        } else {
            'anssi-paragraph'
        }
        "<div class=`"$class`">$encoded</div>"
    }
    return ($markup -join "`n")
}
function New-ADSOpenHtml {
    param($Audit)
    $cardById = @{}
    foreach ($control in $Audit.Controls) {
        $statusMarkup = switch ($control.Status) {
            'Passed' { '<span class="status-icon status-passed" role="img" aria-label="Validé" title="Validé">&#10003;</span>' }
            'Failed' { '<span class="status-icon status-failed" role="img" aria-label="Échec" title="Échec">&#10005;</span>' }
            default  { '<span class="status-icon status-unknown" role="img" aria-label="Non évalué" title="Non évalué">?</span>' }
        }
        $levelBadges = foreach ($level in $control.Levels) {
            $failedClass = if ($control.Status -eq 'Failed' -and $level -in @($control.FailedLevels)) { ' failed-level' } else { '' }
            $title = if ($failedClass) { "Seuil ANSSI $level en échec" } else { "Niveau ANSSI $level applicable" }
            "<span class=`"level level$level$failedClass`" title=`"$title`">$level</span>"
        }
        $details = if ($control.FindingCount) {
            $items = foreach ($finding in @($control.Findings | Select-Object -First 100)) {
                $text = ($finding.PSObject.Properties | ForEach-Object {
                    "$(ConvertTo-HtmlEncoded $_.Name): $(ConvertTo-HtmlEncoded $_.Value)"
                }) -join ' · '
                "<li>$text</li>"
            }
            "<details><summary>$($control.FindingCount) constat(s)</summary><ul>$($items -join '')</ul></details>"
        } else { '' }
        $cardById[$control.Id] = @"
<article class="control $($control.Status.ToLowerInvariant())">
  <header><code>$(ConvertTo-HtmlEncoded $control.Id)</code><span class="item-kind kind-vulnerability">Vulnérabilité</span>$statusMarkup</header>
  <h3>$(ConvertTo-HtmlEncoded $control.Title)</h3>
  <details class="control-guidance">
    <summary>Description détaillée</summary>
    <div class="guidance-content">
      <h4>Description et portée ANSSI</h4>
      $(ConvertTo-AnssiGuidanceHtml $control.DetailedDescription)
      <h4>Recommandations, annotations, limites et acceptations</h4>
      $(ConvertTo-AnssiGuidanceHtml $control.OfficialRecommendation)
      <p class="guidance-source">Copie locale du référentiel ANSSI vérifiée le $(ConvertTo-HtmlEncoded $control.GuidanceReviewedOn) — consultation hors ligne.</p>
    </div>
  </details>
  <p class="levels"><b>Niveau(x) :</b> $($levelBadges -join '')$(if ($control.Status -eq 'Failed') {" · <b>Seuil(s) en échec :</b> $(@($control.FailedLevels) -join ', ')"}) · <b>Source :</b> $(ConvertTo-HtmlEncoded $control.DataSource)</p>
  $details
  <p class="recommendation">$(ConvertTo-HtmlEncoded $control.Recommendation)</p>
</article>
"@
    }
    $levelNames = @{
        1 = 'Mesures indispensables'
        2 = 'Mesures prioritaires'
        3 = 'Renforcement recommandé'
        4 = 'Niveau avancé'
        5 = 'Niveau maîtrisé'
    }
    $sections = foreach ($level in 1..5) {
        $levelControls = @($Audit.Controls | Where-Object {
            $classificationLevels = if ($_.Status -eq 'Failed' -and
                ($_.FailedLevels | Measure-Object).Count) { $_.FailedLevels } else { $_.Levels }
            [int](($classificationLevels | Measure-Object -Minimum).Minimum) -eq $level
        } | Sort-Object @{Expression={if ($_.Status -eq 'Failed') { 0 } else { 1 }}}, Title)
        $failedCount = ($levelControls | Where-Object Status -eq 'Failed' | Measure-Object).Count
        $passedCount = ($levelControls | Where-Object Status -eq 'Passed' | Measure-Object).Count
        $sectionCards = @($levelControls | ForEach-Object { $cardById[$_.Id] })
        @"
<section class="level-section" id="niveau-$level">
  <header class="level-heading">
    <div><span class="level level$level">$level</span><h2>Niveau $level — $($levelNames[$level])</h2></div>
    <p><b>$failedCount échec(s)</b> · $passedCount validé(s) · $($levelControls.Count) contrôle(s)</p>
  </header>
  <div class="controls">$($sectionCards -join "`n")</div>
</section>
"@
    }
    $advisorySections = foreach ($type in @('Warning','Information')) {
        $items = @($Audit.Advisories | Where-Object Type -eq $type)
        $label = if ($type -eq 'Warning') { 'Avertissements' } else { 'Informations' }
        $kindLabel = if ($type -eq 'Warning') { 'Avertissement' } else { 'Information' }
        $kindClass = $type.ToLowerInvariant()
        $cards = foreach ($item in $items) {
            $badges = foreach ($level in $item.Levels) {
                "<span class=`"level level$level`" title=`"Niveau ANSSI indicatif $level`">$level</span>"
            }
            $levelMarkup = if (@($badges).Count) { "<p><b>Niveau(x) indicatif(s) :</b> $($badges -join '')</p>" } else { '' }
            $statusLabel = switch ($item.Status) {
                'Detected' { 'Détecté' }; 'NotDetected' { 'Non détecté' }
                'Observed' { 'Observation' }; default { 'Données indisponibles' }
            }
            $details = if ($item.FindingCount) {
                $itemsMarkup = foreach ($finding in @($item.Findings | Select-Object -First 100)) {
                    $findingText = ($finding.PSObject.Properties | ForEach-Object { "$(ConvertTo-HtmlEncoded $_.Name): $(ConvertTo-HtmlEncoded $_.Value)" }) -join ' · '
                    "<li>$findingText</li>"
                }
                "<details><summary>$($item.FindingCount) élément(s)</summary><ul>$($itemsMarkup -join '')</ul></details>"
            } else { '' }
            $recommendationMarkup = if ($item.Recommendation) { "<p class=`"recommendation`"><b>Recommandation :</b> $(ConvertTo-HtmlEncoded $item.Recommendation)</p>" } else { '' }
            @"
<article class="advisory $kindClass $($item.Status.ToLowerInvariant())">
  <header><code>$(ConvertTo-HtmlEncoded $item.Id)</code><span class="item-kind kind-$kindClass">$kindLabel</span><span class="advisory-status">$statusLabel</span></header>
  <h3>$(ConvertTo-HtmlEncoded $item.Title)</h3>
  $levelMarkup
  <p><b>Date ANSSI :</b> $(ConvertTo-HtmlEncoded $item.PublishedDateDisplay)</p>
  <p>$(ConvertTo-HtmlEncoded $item.Explanation)</p>
  <p class="result-summary"><b>Résultat :</b> $(ConvertTo-HtmlEncoded $item.ResultSummary)</p>
  $details
  $recommendationMarkup
  <p class="data-source"><b>Source :</b> $(ConvertTo-HtmlEncoded $item.DataSource)</p>
</article>
"@
        }
        @"
<section class="advisory-section" id="$($type.ToLowerInvariant())s">
  <header class="level-heading"><div><h2>$label ANSSI</h2></div><p><b>$($items.Count) item(s)</b> · sans effet sur la note</p></header>
  <div class="advisories">$($cards -join "`n")</div>
</section>
"@
    }
    @"
<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ADS-Open — $(ConvertTo-HtmlEncoded $Audit.Domain)</title>
<style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#172033;background:#f3f5f8}
body{margin:0}.hero{position:relative;overflow:hidden;padding:32px max(5vw,24px);background:linear-gradient(125deg,#0b1833 0%,#142d5a 58%,#0c6070 100%);color:#fff}
.hero:after{content:"";position:absolute;width:430px;height:430px;right:-130px;top:-250px;border:70px solid #ffffff0a;border-radius:50%}
.hero-grid{position:relative;z-index:1;display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:24px;max-width:1180px;margin:auto}
.brand-mark{width:112px;height:128px;filter:drop-shadow(0 10px 18px #0006)}.brand-mark svg{width:100%;height:100%}
.eyebrow{margin:0 0 5px;color:#74d6df;font-weight:700;letter-spacing:.18em;text-transform:uppercase}.hero h1{font-size:clamp(2rem,5vw,3.45rem);line-height:1;margin:0}
.hero .subtitle{margin:10px 0 0;color:#d8e5f5;font-size:1.05rem}.hero-score{text-align:center}.hero-score .score-label{display:block;margin-top:7px;color:#d8e5f5;font-size:.82rem;text-transform:uppercase;letter-spacing:.1em}
.environment{position:relative;z-index:1;display:flex;justify-content:center;gap:12px;flex-wrap:wrap;max-width:1180px;margin:24px auto 0}
.environment div{min-width:190px;padding:11px 15px;border:1px solid #ffffff24;border-radius:9px;background:#ffffff0c;backdrop-filter:blur(4px)}
.environment span{display:block;color:#9db4d2;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}.environment b{font-size:1rem}
.score{display:inline-grid;place-items:center;width:92px;height:92px;border-radius:50%;font-size:42px;font-weight:700}
main{max-width:1180px;margin:auto;padding:28px}.summary{display:flex;gap:16px;flex-wrap:wrap}.summary div,.control{background:#fff;border-radius:10px;box-shadow:0 2px 12px #0001;padding:16px}
.summary div{min-width:150px}.controls,.advisories{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:16px}.control,.advisory{min-width:0;box-sizing:border-box}.advisory{background:#fff;border-radius:10px;box-shadow:0 2px 12px #0001;padding:16px;border-left:6px solid #6c757d}.advisory.warning{border-color:#e5a000;background:#fffaf0}.advisory.warning.detected{background:#fff2d8}.advisory.information{border-color:#2683bd;background:#f5faff}.advisory.dataunavailable{border-color:#7d8590;background:#f6f7f9}.advisory header{display:flex;align-items:flex-start;gap:8px;flex-wrap:wrap}.advisory h3{margin-bottom:8px}.advisory-status{font-weight:700;flex:0 1 auto;overflow-wrap:anywhere}.result-summary{padding:9px;border-radius:6px;background:#ffffffa8}.data-source{font-size:.85rem;color:#667085;overflow-wrap:anywhere}
.control{border-left:6px solid #8792a2}.control.failed{border-color:#c62828;background:#fff3f3}.control.passed{border-color:#2e7d32}.control.notevaluated{border-color:#6c757d;background:#f8f9fa}
.control header{display:flex;align-items:flex-start;gap:8px;flex-wrap:wrap}.control header span{font-weight:700}.control h3{margin-bottom:8px}.control header code,.advisory header code{flex:1 1 180px;min-width:0;white-space:normal;overflow-wrap:anywhere;word-break:break-word}
.status-icon{display:inline-grid;place-items:center;width:1.65em;height:1.65em;border-radius:50%;font-size:1.15rem;font-weight:800;line-height:1}.status-passed{background:#e6f4e8;color:#1b7f32}.status-failed{background:#fde8e8;color:#c62828}.status-unknown{background:#eceff3;color:#5f6872}
.control code a,.advisory code a{color:inherit}.control.notevaluated header span{color:#5f6872}.item-kind{margin-left:0;flex:0 0 auto;max-width:100%;padding:.28em .65em;border-radius:999px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em}.status-icon{flex:0 0 auto}.kind-vulnerability{background:#fde8e8;color:#a51f1f}.kind-warning{background:#fff0c2;color:#745200}.kind-information{background:#dceeff;color:#135b8a}
.level{display:inline-grid;place-items:center;min-width:1.65em;height:1.65em;margin:0 .18em;border-radius:50%;font-weight:700}
.level1{background:#dc3545;color:#fff}.level2{background:#ffa500;color:#000}.level3{background:#f0e68c;color:#000}
.level4{background:#007bff;color:#fff}.level5{background:#28a745;color:#fff}
.failed-level{outline:3px solid #172033;outline-offset:2px}
.legend{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin:18px 0}.legend span.label{margin-right:8px}
.recommendation{background:#eef3f8;padding:10px;border-radius:6px}li{margin:6px 0;overflow-wrap:anywhere}
.control-guidance{margin:12px 0;border:1px solid #d7dde6;border-radius:8px;background:#f8fafc}.control-guidance>summary{cursor:pointer;padding:10px 12px;font-weight:700}.guidance-content{padding:0 12px 12px}.guidance-content h4{margin:16px 0 8px}.anssi-paragraph{margin:8px 0;line-height:1.48;overflow-wrap:anywhere}.anssi-subheading{margin:15px 0 6px;font-weight:800;color:#25364d}.anssi-callout{margin:12px 0;padding:10px 12px;border-left:4px solid #53718f;border-radius:5px;background:#eaf0f6;line-height:1.45;overflow-wrap:anywhere}.guidance-source{font-size:.82rem;color:#667085}
.notice{background:#fff3cd;color:#5f4600;padding:12px;border-radius:8px;margin-top:18px}
.level-nav{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0}.level-nav a{display:flex;align-items:center;gap:5px;background:#fff;color:#172033;text-decoration:none;padding:8px 12px;border-radius:8px;box-shadow:0 2px 8px #0001}
.level-section{margin-top:34px;scroll-margin-top:12px}.level-heading{display:flex;justify-content:space-between;align-items:end;gap:18px;border-bottom:2px solid #dce1e8;margin-bottom:16px;padding-bottom:10px}
.level-heading>div{display:flex;align-items:center;gap:10px}.level-heading h2,.level-heading p{margin:0}.level-heading .level{font-size:1.25rem}
@media(max-width:700px){.level-heading{align-items:start;flex-direction:column}.controls{grid-template-columns:1fr}}
.footer{margin-top:42px;padding:20px 0;border-top:1px solid #d7dde6;color:#667085;text-align:center}
@media(max-width:760px){.hero-grid{grid-template-columns:auto 1fr}.hero-score{grid-column:1/-1}.brand-mark{width:82px;height:94px}}
</style></head>
<body><section class="hero">
<div class="hero-grid">
  <div class="brand-mark" aria-label="Emblème ADS-Open">
    <svg viewBox="0 0 112 128" role="img" aria-hidden="true">
      <defs><linearGradient id="shield" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#59d4df"/><stop offset="1" stop-color="#147c93"/></linearGradient></defs>
      <path d="M56 3 105 21v38c0 31-20 53-49 66C27 112 7 90 7 59V21Z" fill="url(#shield)" stroke="#fff" stroke-width="3"/>
      <path d="M56 13 94 27v31c0 24-14 42-38 54C32 100 18 82 18 58V27Z" fill="#10264d"/>
      <path d="M34 72 56 36l22 36-8 16H42Z" fill="none" stroke="#fff" stroke-width="6" stroke-linejoin="round"/>
      <circle cx="56" cy="72" r="6" fill="#59d4df"/>
      <text x="56" y="103" text-anchor="middle" fill="#fff" font-family="Segoe UI,Arial" font-size="11" font-weight="700">ADS OPEN</text>
    </svg>
  </div>
  <div><p class="eyebrow">ADS-Open · Audit indépendant</p><h1>Pré-audit ANSSI</h1>
  <p class="subtitle">Évaluation de la posture de sécurité Active Directory</p></div>
  <div class="hero-score"><div class="score level$($Audit.Score.Level)">$($Audit.Score.Level)</div><span class="score-label">Niveau obtenu / 5</span></div>
</div>
<div class="environment">
  <div><span>Domaine audité</span><b>$(ConvertTo-HtmlEncoded $Audit.Domain)</b></div>
  <div><span>Niveau fonctionnel forêt</span><b>$(ConvertTo-HtmlEncoded $Audit.ForestFunctionalLevel)</b></div>
  <div><span>Niveau fonctionnel domaine</span><b>$(ConvertTo-HtmlEncoded $Audit.DomainFunctionalLevel)</b></div>
  <div><span>Contrôleurs de domaine</span><b>$(ConvertTo-HtmlEncoded $Audit.DomainControllerCount)</b></div>
  <div><span>Sites Active Directory</span><b>$(ConvertTo-HtmlEncoded $Audit.SiteCount)</b></div>
  <div><span>Utilisateurs</span><b>$(ConvertTo-HtmlEncoded $Audit.UserCount)</b></div>
  <div><span>Ordinateurs</span><b>$(ConvertTo-HtmlEncoded $Audit.ComputerCount)</b></div>
  <div><span>Version ADS-Open</span><b>v$(ConvertTo-HtmlEncoded $Audit.Version)</b></div>
  <div title="$(ConvertTo-HtmlEncoded $Audit.Score.SuccessPointsMethod)"><span>Points cumulés validés</span><b>$(ConvertTo-HtmlEncoded $Audit.Score.SuccessPoints) pts</b></div>
  <div><span>Généré le</span><b>$(ConvertTo-HtmlEncoded $Audit.GeneratedDisplay)</b></div>
</div></section>
<main><p class="notice">Réimplémentation indépendante fondée sur les données ORADAD et les contrôles publics de l'ANSSI. Ce rapport n'est ni produit ni certifié par l'ANSSI. Le score en points est une estimation ADS-Open : le barème officiel ADS n'est pas public.</p>
<section class="legend"><b>Échelle ANSSI :</b><span class="level level1">1</span><span class="label">Critique</span><span class="level level2">2</span><span class="level level3">3</span><span class="level level4">4</span><span class="level level5">5</span><span class="label">Maîtrisé</span></section>
<section class="summary"><div><b>$($Audit.Score.Failed)</b><br>Échecs</div><div><b>$($Audit.Score.Passed)</b><br>Validés</div><div><b>$($Audit.Score.NotEvaluated)</b><br>Non évalués</div><div><b>$($Audit.Controls.Count)</b><br>Vulnérabilités</div><div><b>$(@($Audit.Advisories | Where-Object Type -eq 'Warning').Count)</b><br>Avertissements</div><div><b>$(@($Audit.Advisories | Where-Object Type -eq 'Information').Count)</b><br>Informations</div></section>
<nav class="level-nav" aria-label="Accès aux niveaux ANSSI"><a href="#niveau-1"><span class="level level1">1</span>Niveau 1</a><a href="#niveau-2"><span class="level level2">2</span>Niveau 2</a><a href="#niveau-3"><span class="level level3">3</span>Niveau 3</a><a href="#niveau-4"><span class="level level4">4</span>Niveau 4</a><a href="#niveau-5"><span class="level level5">5</span>Niveau 5</a></nav>
$($sections -join "`n")
<section class="advisory-intro"><h2>Observations complémentaires ANSSI</h2><p>Ces avertissements et informations sont présentés à titre contextuel. Ils ne produisent aucun échec et ne modifient ni le niveau ni les points cumulés.</p></section>
$($advisorySections -join "`n")
<footer class="footer">ADS-Open v$(ConvertTo-HtmlEncoded $Audit.Version) · Pré-audit ANSSI indépendant · © $(Get-Date -Format yyyy) Pierre Faurant</footer>
</main></body></html>
"@
}

function Invoke-ADSOpenAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Html','Json','Both')][string]$Format = 'Both'
    )
    $root = Resolve-OradadRoot $InputPath
    $dataset = New-OradadDataset $root
    $analysis = Get-ADSOpenAnalysis $dataset
    $controls = @($analysis.Controls)
    $metadata = @{}
    foreach ($row in Get-OradadRows $dataset 'metadata.tsv') { $metadata[$row.key] = $row.value }
    $score = Get-ADSOpenScore $controls
    $advisories = @($analysis.Advisories)
    $auditDomain = if ($metadata.ContainsKey('domain') -and $metadata['domain']) {
        $metadata['domain']
    } else {
        Split-Path (Split-Path $root -Parent) -Leaf
    }
    function Format-FunctionalLevel {
        param($Value)
        $version = -1
        if (-not [int]::TryParse([string]$Value,[ref]$version)) { return 'Non renseigné' }
        $names = @{
            0='Windows 2000'; 1='Windows Server 2003 intermédiaire'; 2='Windows Server 2003'
            3='Windows Server 2008'; 4='Windows Server 2008 R2'; 5='Windows Server 2012'
            6='Windows Server 2012 R2'; 7='Windows Server 2016 ou ultérieur'
        }
        if ($names.ContainsKey($version)) { return "$($names[$version]) (niveau $version)" }
        return "Version Active Directory $version"
    }
    $domainRoot = Get-OradadRows $dataset "domain\$auditDomain\root.tsv" | Select-Object -First 1
    $forestRoot = Get-OradadRows $dataset 'configuration\crossRefContainer.tsv' | Select-Object -First 1
    $auditUsers = @(Get-OradadRows $dataset "domain\$auditDomain\user.tsv")
    $auditComputers = @(Get-OradadRows $dataset "domain\$auditDomain\computer.tsv")
    $auditSites = @(Get-OradadRows $dataset 'configuration\site.tsv')
    $domainFunctionalLevel = Format-FunctionalLevel (Get-OradadValue $domainRoot 'msDS-Behavior-Version')
    $forestFunctionalLevel = Format-FunctionalLevel (Get-OradadValue $forestRoot 'msDS-Behavior-Version')
    $audit = [pscustomobject]@{
        Product       = 'ADS-Open'
        Version       = $script:ADSOpenVersion
        GeneratedAt   = (Get-Date).ToString('o')
        InputRoot     = $root
        Domain        = $auditDomain
        ForestFunctionalLevel = $forestFunctionalLevel
        DomainFunctionalLevel = $domainFunctionalLevel
        DomainControllerCount = @($auditComputers | Where-Object {
            $_.primaryGroupID -in @('516','521')
        }).Count
        SiteCount      = $auditSites.Count
        UserCount      = $auditUsers.Count
        ComputerCount  = $auditComputers.Count
        GeneratedDisplay = (Get-Date).ToString('dd/MM/yyyy HH:mm')
        OradadVersion = $metadata.oradad_version
        Score         = $score
        Controls      = $controls
        Advisories    = $advisories
        Disclaimer    = "Réimplémentation indépendante; ce résultat n'est pas un rapport ADS officiel de l'ANSSI."
    }
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    if ($Format -in @('Json','Both')) {
        $audit | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputPath 'report.json') -Encoding UTF8
    }
    if ($Format -in @('Html','Both')) {
        New-ADSOpenHtml $audit | Set-Content -LiteralPath (Join-Path $OutputPath 'report.html') -Encoding UTF8
    }
    $audit
}

Export-ModuleMember -Function Invoke-ADSOpenAudit

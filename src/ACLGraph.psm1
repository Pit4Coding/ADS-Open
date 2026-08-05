Set-StrictMode -Version 2.0

function Convert-HexToBytes {
    param([string]$Hex)
    if ([string]::IsNullOrWhiteSpace($Hex) -or ($Hex.Length % 2)) { return $null }
    try {
        $bytes = New-Object byte[] ($Hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
        }
        return $bytes
    } catch { return $null }
}

function Expand-AdGenericAccessMask {
    param([int64]$Mask)

    # Mappage GENERIC_* du service d'annuaire. Les ACE de refus portent
    # souvent un droit AD spécifique alors que l'ACE d'autorisation utilise
    # GenericAll/GenericWrite : les deux doivent être comparés après expansion.
    if (($Mask -band 0x10000000) -ne 0) { # GENERIC_ALL
        $Mask = ($Mask -band (-bnot [int64]0x10000000)) -bor [int64]0x000F01FF
    }
    if (($Mask -band 0x40000000) -ne 0) { # GENERIC_WRITE
        $Mask = ($Mask -band (-bnot [int64]0x40000000)) -bor [int64]0x00020028
    }
    if (($Mask -band 0x80000000) -ne 0) { # GENERIC_READ
        $Mask = ($Mask -band (-bnot [int64]0x80000000)) -bor [int64]0x00020094
    }
    if (($Mask -band 0x20000000) -ne 0) { # GENERIC_EXECUTE
        $Mask = ($Mask -band (-bnot [int64]0x20000000)) -bor [int64]0x00020004
    }
    return $Mask
}

function Get-ADSOpenAclAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Objects,
        [Parameter(Mandatory)][object[]]$Principals,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Groups,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Attributes,
        [Parameter(Mandatory)][string]$DomainSid,
        [Parameter(Mandatory)][string[]]$Tier0Dns,
        [switch]$IncludePaths
    )

    $sidToDn = @{}
    foreach ($principal in $Principals) {
        $sid = if ($principal.PSObject.Properties['objectSid'] -and $principal.objectSid) {
            [string]$principal.objectSid
        } elseif ($principal.PSObject.Properties['securityIdentifier']) {
            [string]$principal.securityIdentifier
        } else { '' }
        if ($sid) { $sidToDn[$sid] = [string]$principal.dn }
    }
    $guidNames = @{}
    foreach ($attribute in $Attributes) {
        if ($attribute.schemaIDGUID) { $guidNames[[string]$attribute.schemaIDGUID.ToLowerInvariant()] = [string]$attribute.lDAPDisplayName }
        if ($attribute.attributeSecurityGUID -and -not $guidNames.ContainsKey([string]$attribute.attributeSecurityGUID.ToLowerInvariant())) {
            $guidNames[[string]$attribute.attributeSecurityGUID.ToLowerInvariant()] = "property-set:$($attribute.attributeSecurityGUID)"
        }
    }
    $extendedRights = @{
        '00299570-246d-11d0-a768-00aa006e0529' = 'ResetPassword'
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DCSyncGetChanges'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DCSyncGetChangesAll'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'DCSyncFilteredSet'
        'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'ChangePassword'
        '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'CertificateEnrollment'
        'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'CertificateAutoEnrollment'
    }
    $safeSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sid in @(
        'S-1-5-18', 'S-1-5-9', 'S-1-5-10', 'S-1-5-32-544',
        "$DomainSid-512", "$DomainSid-516", "$DomainSid-518", "$DomainSid-519",
        "$DomainSid-526", "$DomainSid-527"
    )) { [void]$safeSids.Add($sid) }

    $relations = [System.Collections.Generic.List[object]]::new()
    $parseErrors = [System.Collections.Generic.List[object]]::new()
    $descriptorCount = 0
    foreach ($object in $Objects) {
        if ($object.nTSecurityDescriptor) { $descriptorCount++ }
        if (-not $object.dn -or -not $object.nTSecurityDescriptor) { continue }
        $bytes = Convert-HexToBytes ([string]$object.nTSecurityDescriptor)
        if (-not $bytes) {
            $parseErrors.Add([pscustomobject]@{ Dn = $object.dn; Error = 'InvalidHex' })
            continue
        }
        try {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
        } catch {
            $parseErrors.Add([pscustomobject]@{ Dn = $object.dn; Error = $_.Exception.Message })
            continue
        }

        $ownerSid = if ($sd.Owner) { $sd.Owner.Value } else { $null }
        if ($ownerSid -and -not $safeSids.Contains($ownerSid)) {
            $relations.Add([pscustomobject]@{
                SourceSid = $ownerSid; SourceDn = $sidToDn[$ownerSid]; TargetDn = [string]$object.dn
                Right = 'Owner'; ObjectType = ''; Inherited = $false; AccessMask = 0
            })
        }

        if (-not $sd.DiscretionaryAcl) { continue }
        $denyMasks = @{}
        foreach ($denyAce in $sd.DiscretionaryAcl) {
            if ($denyAce.AceType -notin @(
                [System.Security.AccessControl.AceType]::AccessDenied,
                [System.Security.AccessControl.AceType]::AccessDeniedObject
            )) { continue }
            if (([int]$denyAce.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
            $denyType = ''
            if ($denyAce -is [System.Security.AccessControl.ObjectAce] -and
                ([int]$denyAce.ObjectAceFlags -band [int][System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
                $denyType = $denyAce.ObjectAceType.ToString().ToLowerInvariant()
            }
            $denyKey = "$($denyAce.SecurityIdentifier.Value)|$denyType"
            $denyMask = Expand-AdGenericAccessMask ([int64]$denyAce.AccessMask)
            $denyMasks[$denyKey] = [int64]$denyMasks[$denyKey] -bor $denyMask
        }
        foreach ($ace in $sd.DiscretionaryAcl) {
            if ($ace.AceType -notin @(
                [System.Security.AccessControl.AceType]::AccessAllowed,
                [System.Security.AccessControl.AceType]::AccessAllowedObject
            )) { continue }
            if (([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
            $sid = $ace.SecurityIdentifier.Value
            if ($safeSids.Contains($sid)) { continue }
            $rawMask = [int64]$ace.AccessMask
            $mask = Expand-AdGenericAccessMask $rawMask
            $objectType = ''
            if ($ace -is [System.Security.AccessControl.ObjectAce] -and
                ([int]$ace.ObjectAceFlags -band [int][System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
                $objectType = $ace.ObjectAceType.ToString().ToLowerInvariant()
            }
            $rights = [System.Collections.Generic.List[string]]::new()
            $specificDeny = "$sid|$objectType"
            $broadDeny = "$sid|"
            if ($denyMasks.ContainsKey($specificDeny)) { $mask = $mask -band (-bnot [int64]$denyMasks[$specificDeny]) }
            if ($objectType -and $denyMasks.ContainsKey($broadDeny)) { $mask = $mask -band (-bnot [int64]$denyMasks[$broadDeny]) }
            if (($mask -band 0x000F01FF) -eq 0x000F01FF) { $rights.Add('GenericAll') }
            if ($mask -band 0x00040000) { $rights.Add('WriteDacl') }
            if ($mask -band 0x00080000) { $rights.Add('WriteOwner') }
            if (($rawMask -band 0x40000000) -ne 0 -and
                ($mask -band 0x00020028) -eq 0x00020028) { $rights.Add('GenericWrite') }
            if ($mask -band 0x00000001) { $rights.Add('CreateChild') }
            if ($mask -band 0x00000002) { $rights.Add('DeleteChild') }
            if ($mask -band 0x00000020) {
                $name = if ($objectType -and $guidNames.ContainsKey($objectType)) { $guidNames[$objectType] } else { $objectType }
                $sensitive = @(
                    'member', 'servicePrincipalName', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                    'msDS-KeyCredentialLink', 'msDS-AllowedToDelegateTo', 'altSecurityIdentities',
                    'userAccountControl', 'gPLink', 'msDS-GroupMSAMembership', 'msDS-ManagedPassword'
                )
                if (-not $objectType) { $rights.Add('WriteAllProperties') }
                elseif ($name -in $sensitive) { $rights.Add("WriteProperty:$name") }
            }
            if ($mask -band 0x00000100) {
                if (-not $objectType) { $rights.Add('AllExtendedRights') }
                elseif ($extendedRights.ContainsKey($objectType)) { $rights.Add("ExtendedRight:$($extendedRights[$objectType])") }
            }
            foreach ($right in $rights | Select-Object -Unique) {
                $relations.Add([pscustomobject]@{
                    SourceSid = $sid
                    SourceDn = $sidToDn[$sid]
                    TargetDn = [string]$object.dn
                    Right = $right
                    ObjectType = $objectType
                    Inherited = (([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0)
                    AccessMask = $ace.AccessMask
                })
            }
        }
    }

    $paths = [System.Collections.Generic.List[object]]::new()
    if ($IncludePaths) {
        # La construction exhaustive des chemins est coûteuse sur les grands
        # domaines. Elle reste disponible à la demande, mais les contrôles du
        # rapport utilisent les relations ACL directes et n'en dépendent pas.
        $adjacency = @{}
        function Add-GraphEdge([string]$From, [string]$To, [string]$Kind) {
            if (-not $From -or -not $To) { return }
            if (-not $adjacency.ContainsKey($From)) { $adjacency[$From] = [System.Collections.Generic.List[object]]::new() }
            $adjacency[$From].Add([pscustomobject]@{ To = $To; Kind = $Kind })
        }
        foreach ($group in $Groups) {
            foreach ($member in @([string]$group.member -split ';' | Where-Object { $_ })) {
                Add-GraphEdge $member ([string]$group.dn) 'MemberOf'
            }
        }
        foreach ($relation in $relations) {
            Add-GraphEdge ([string]$relation.SourceDn) ([string]$relation.TargetDn) ([string]$relation.Right)
        }

        $tier0Set = [System.Collections.Generic.HashSet[string]]::new($Tier0Dns, [System.StringComparer]::OrdinalIgnoreCase)
        foreach ($source in @($adjacency.Keys)) {
            if ($tier0Set.Contains($source)) { continue }
            $queue = [System.Collections.Generic.Queue[object]]::new()
            $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $queue.Enqueue([pscustomobject]@{ Node = $source; Nodes = @($source); Edges = @() })
            [void]$visited.Add($source)
            while ($queue.Count -and $visited.Count -lt 5000) {
                $state = $queue.Dequeue()
                if ($state.Nodes.Count -gt 8) { continue }
                if (-not $adjacency.ContainsKey([string]$state.Node)) { continue }
                foreach ($edge in $adjacency[$state.Node].ToArray()) {
                    $nodes = @($state.Nodes) + $edge.To
                    $edges = @($state.Edges) + $edge.Kind
                    if ($tier0Set.Contains($edge.To)) {
                        $paths.Add([pscustomobject]@{ Source = $source; Target = $edge.To; Nodes = $nodes; Edges = $edges })
                        continue
                    }
                    if ($visited.Add($edge.To)) {
                        $queue.Enqueue([pscustomobject]@{ Node = $edge.To; Nodes = $nodes; Edges = $edges })
                    }
                }
            }
        }
    }

    [pscustomobject]@{
        Relations   = @($relations)
        Paths       = @($paths)
        ParseErrors = @($parseErrors)
        ObjectCount = $Objects.Count
        ParsedCount = $descriptorCount - $parseErrors.Count
    }
}

Export-ModuleMember -Function Get-ADSOpenAclAnalysis

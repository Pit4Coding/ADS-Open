# Evaluateurs des observations complémentaires ANSSI.
# Les colonnes ORADAD varient selon la version et le type d'objet.
Set-StrictMode -Version 1.0
# Ce script est exécuté dans la portée de Get-ADSOpenControls afin de réutiliser
# les données et le graphe ACL déjà chargés.
$catalogPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'data\anssi-advisories.tsv'
$advisoryResults = [System.Collections.Generic.List[object]]::new()
$sysvol = @(Get-OradadRows $Dataset "$prefix\sysvol.tsv")
$metadataRows = @(Get-OradadRows $Dataset 'metadata.tsv')
$controlById = @{}
foreach ($control in $results) { $controlById[$control.Id] = $control }

function Test-ADSOpenWellKnownSid {
    param([AllowNull()][string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
    try {
        $identifier = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        foreach ($kind in [Enum]::GetValues([System.Security.Principal.WellKnownSidType])) {
            try {
                if ($identifier.IsWellKnown($kind)) { return $true }
            } catch { }
        }
    } catch {
        return $false
    }
    # Familles générées dynamiquement mais réservées par Windows : SID de
    # session, package d'authentification, service, machine virtuelle, etc.
    return $Sid -match '^S-1-(?:0|1|2|3|4|9|11|15|16|18)(?:-|$)' -or
        $Sid -match '^S-1-5-(?:5-|32-|64-|80-|82-|83-|84-|90-|96-)'
}
function New-AdvisoryResult {
    param($Item,[object[]]$Findings,[string]$Explanation,[string]$Recommendation,
        [string]$Source,[string]$Availability = 'Evaluated')
    $findingArray = @($Findings)
    $findingCount = $findingArray.Count
    # Conserve un échantillon vérifiable : verdict et compteur portent sur tous les résultats.
    $findingSample = @($findingArray | Select-Object -First 200)
    $type = [string]$Item.Type
    $status = if ($Availability -ne 'Evaluated') { 'DataUnavailable' }
        elseif ($type -eq 'Warning') { if ($findingCount) { 'Detected' } else { 'NotDetected' } }
        else { 'Observed' }
    $summary = if ($status -eq 'Detected') { "$findingCount observation(s) nécessitent une vérification." }
        elseif ($status -eq 'NotDetected') { 'Aucun élément correspondant au critère nʼa été détecté.' }
        elseif ($status -eq 'Observed') { "$findingCount élément(s) inventorié(s)." }
        else { 'Les données requises ne sont pas présentes dans cet extract ORADAD.' }
    [pscustomobject]@{
        Id=$Item.Id; Type=$type; Title=$Item.Title
        Levels=@($Item.Levels -split ',' | Where-Object { $_ } | ForEach-Object { [int]$_ })
        PublishedDate=$Item.PublishedDate
        PublishedDateDisplay=([datetime]::ParseExact($Item.PublishedDate,'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture).ToString('dd/MM/yyyy'))
        Status=$status; ResultSummary=$summary; FindingCount=$findingCount
        Findings=$findingSample; Explanation=$Explanation
        Recommendation=$(if ($status -eq 'Detected') { $Recommendation } else { '' })
        DataSource=$Source; Availability=$Availability; AffectsScore=$false
        Reference="https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#$($Item.Id)"
    }
}

function Select-RecentOrDormant {
    param([object[]]$Accounts,[int]$Days=90)
    $limit=$now.AddDays(-$Days)
    @($Accounts | Where-Object {
        -not (Test-UacFlag $_ 2) -and
        ((-not $_.lastLogonTimestamp) -or ((Convert-OradadDate $_.lastLogonTimestamp) -lt $limit))
    } | Select-Object dn,sAMAccountName,lastLogonTimestamp)
}

$activeUsers = @($users | Where-Object { -not (Test-UacFlag $_ 2) })
$allPrincipals = @($users)+@($computers)+@($groups)+@($smsa)+@($gmsa)
$privilegedAccountDns = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($account in $privilegedAccounts){if($account.dn){[void]$privilegedAccountDns.Add($account.dn)}}
$topByDn=@{}
foreach($object in $allObjects){if($object.dn){$topByDn[[string]$object.dn]=$object}}

foreach ($item in Import-Csv -LiteralPath $catalogPath -Delimiter "`t") {
    $findings=@(); $source=''; $available='Evaluated'
    $explanation="Ce point complémentaire ANSSI examine « $($item.Title) » sans modifier la note globale."
    $recommendation="Examiner les objets listés et appliquer les mesures détaillées dans la fiche ANSSI $($item.Id)."
    switch ($item.Id) {
        'info_gpo' {
            $findings=@($gpos|ForEach-Object{$top=$topByDn[$_.dn];[pscustomobject]@{dn=$_.dn;cn=$_.cn;versionNumber=$_.versionNumber;whenChanged=$top.whenChanged}})
            $source="$prefix\gpo.tsv"; $explanation='Inventaire des GPO et de leur dernière modification connue.'
        }
        'info_gpo_sysvol' {
            $findings=@($sysvol|Where-Object filename|Select-Object path,filename,ftCreaftLastWriteTimetionTime,filesize,errorCode)
            $source="$prefix\sysvol.tsv"; $explanation='Inventaire des fichiers SYSVOL associés aux stratégies de groupe.'
        }
        'info_keycredentiallink_dc' {
            $findings=@($computers|Where-Object{($_.primaryGroupID-in@('516','521'))-and $_.'msDS-KeyCredentialLink'}|Select-Object dn,sAMAccountName,'msDS-KeyCredentialLink')
            $source="$prefix\computer.tsv"; $explanation='Recense les contrôleurs de domaine utilisant une authentification par clé publique.'
        }
        'info_keycredentiallink_priv' {
            $findings=@($privilegedAccounts|Where-Object{$_.'msDS-KeyCredentialLink'}|Select-Object dn,sAMAccountName,'msDS-KeyCredentialLink')
            $source="$prefix\user.tsv; $prefix\computer.tsv"; $explanation='Recense les comptes privilégiés possédant une clé dʼauthentification.'
        }
        'info_keycredentiallink_silo' {
            $findings=@($computers|Where-Object{$_.'msDS-AssignedAuthNPolicySilo'-and $_.'msDS-KeyCredentialLink'}|Select-Object dn,sAMAccountName,'msDS-AssignedAuthNPolicySilo','msDS-KeyCredentialLink')
            $source="$prefix\computer.tsv"; $explanation='Recense les machines membres dʼun silo et configurées pour lʼauthentification par clé.'
        }
        'info_laps' {
            $eligible=@($computers|Where-Object{-not(Test-UacFlag $_ 2)-and $_.primaryGroupID-notin@('516','521')})
            $covered=@($eligible|Where-Object{$_.'ms-Mcs-AdmPwdExpirationTime'-or $_.'msLAPS-PasswordExpirationTime_int'})
            $findings=@([pscustomobject]@{EligibleComputers=$eligible.Count;CoveredComputers=$covered.Count;CoveragePercent=$(if($eligible.Count){[math]::Round(100*$covered.Count/$eligible.Count,1)}else{0})})
            $source="$prefix\computer.tsv"; $explanation='Mesure la couverture des postes et serveurs éligibles par Microsoft LAPS.'
        }
        'info_laps_missing' {
            $findings=@($computers|Where-Object{-not(Test-UacFlag $_ 2)-and $_.primaryGroupID-notin@('516','521')-and -not $_.'ms-Mcs-AdmPwdExpirationTime'-and -not $_.'msLAPS-PasswordExpirationTime_int'}|Select-Object dn,sAMAccountName,operatingSystem)
            $source="$prefix\computer.tsv"; $explanation='Liste les machines actives sans trace dʼutilisation de LAPS.'
        }
        'info_password_policy_pso' {
            $findings=@($passwordSettings|Select-Object *)
            $source="$prefix\passwordSettings.tsv"; $explanation='Inventaire des politiques de mot de passe affinées présentes dans le domaine.'
        }
        'info_privileged_members_recent_changes' {
            $limit=$now.AddDays(-30);$findings=@($privilegedGroups|ForEach-Object{$top=$topByDn[$_.dn];if($top.whenChanged-and(Convert-OradadDate $top.whenChanged)-ge$limit){[pscustomobject]@{dn=$_.dn;whenChanged=$top.whenChanged;member=$_.member}}})
            $source="$prefix\group.tsv; $prefix\top.tsv"; $explanation='Signale les groupes privilégiés modifiés au cours des trente derniers jours.'
        }
        'info_sd' {
            $findings=@($acl.Relations|Where-Object{$_.SourceSid-eq'S-1-5-7'}|Select-Object SourceSid,SourceDn,TargetDn,Right,Inherited)
            $source='nTSecurityDescriptor'; $explanation='Inventorie les relations ACL accordées à Everyone ou Anonymous Logon.'
        }
        'info_sd_missing_au_lc' {
            $available='DataUnavailable';$source='nTSecurityDescriptor';$explanation='Recherche les OU dont le contenu ne peut pas être listé par les utilisateurs authentifiés.'
        }
        'info_sd_protected_ou' {
            $findings=@($ous|ForEach-Object{$top=$topByDn[$_.dn];if($top.nTSecurityDescriptor-match '(?i)D:P'){[pscustomobject]@{dn=$_.dn;Reason='DACL protégée'}}})
            $source="$prefix\top.tsv";$explanation='Liste les OU dont la DACL bloque lʼhéritage des permissions.'
        }
        'info_user_accounts_dormant' {
            $findings=Select-RecentOrDormant $users 90;$source="$prefix\user.tsv";$explanation='Inventorie les comptes actifs sans activité récente.'
        }
        'warning_admincount' {
            $findings=@($allPrincipals|Where-Object{[string]$_.adminCount-eq'1'}|Select-Object dn,sAMAccountName,adminCount)
            $source='tables de comptes et groupes';$explanation='Détecte les objets marqués adminCount=1, généralement protégés par AdminSDHolder.'
        }
        'warning_admincount_0' {
            $findings=@($allPrincipals|Where-Object{[string]$_.adminCount-eq'0'}|Select-Object dn,sAMAccountName,adminCount)
            $source='tables de comptes et groupes';$explanation='Détecte les objets portant explicitement adminCount=0.'
        }
        'warning_dnszone_duplicated_zones' {
            $findings=@($dnsZones|Group-Object{[string]$_.dc}|Where-Object{$_.Name-and$_.Count-gt1}|ForEach-Object{[pscustomobject]@{Zone=$_.Name;Count=$_.Count;Locations=(@($_.Group.dn)-join'; ')}})
            $source='dnsZone.tsv';$explanation='Recherche un même nom de zone DNS présent dans plusieurs partitions.'
        }
        'warning_dont_expire' {
            $findings=@($activeUsers|Where-Object{Test-UacFlag $_ 65536}|Select-Object dn,sAMAccountName,pwdLastSet)
            $source="$prefix\user.tsv";$explanation='Liste les comptes actifs dont le mot de passe est configuré pour ne jamais expirer.'
        }
        'warning_dump_error_rp' {
            $available='DataUnavailable';$source='Journal détaillé de collecte ORADAD';$explanation='Repère les attributs que le compte de collecte nʼa pas été autorisé à lire.'
        }
        'warning_dump_error_vuln_rp' {
            $available='DataUnavailable';$source='Journal détaillé de collecte ORADAD';$explanation='Suit les erreurs de lecture que lʼANSSI annonce comme devenant bloquantes.'
        }
        'warning_logonscript_priv' {
            $findings=@($privilegedAccounts|Where-Object{$_.scriptPath}|Select-Object dn,sAMAccountName,scriptPath)
            $source="$prefix\user.tsv";$explanation='Recherche un script de connexion configuré sur un compte privilégié.'
        }
        'warning_password_change' {
            $limit=$now.AddYears(-3);$findings=@($activeUsers|Where-Object{$_.pwdLastSet-and(Convert-OradadDate $_.pwdLastSet)-lt$limit}|Select-Object dn,sAMAccountName,pwdLastSet)
            $source="$prefix\user.tsv";$explanation='Recherche les comptes actifs dont le mot de passe nʼa pas changé depuis trois ans.'
        }
        'warning_privileged_members' {
            $threshold=[math]::Max(50,3*[math]::Max(1,@($crossRefs|Where-Object dnsRoot).Count));if($privilegedAccountsForCount.Count-gt$threshold){$findings=@([pscustomobject]@{Count=$privilegedAccountsForCount.Count;Threshold=$threshold})}
            $source="$prefix\group.tsv; $prefix\user.tsv";$explanation='Compare le nombre de comptes privilégiés au seuil indicatif ANSSI.'
        }
        'warning_privileged_members_expired_disabled' {
            $findings=@($privilegedAccounts|Where-Object{(Test-UacFlag $_ 2)-or($_.accountExpires-and(Convert-OradadDate $_.accountExpires)-lt$now)}|Select-Object dn,sAMAccountName,userAccountControl,accountExpires)
            $source="$prefix\user.tsv; $prefix\computer.tsv";$explanation='Liste les comptes privilégiés désactivés ou expirés.'
        }
        'warning_privileged_members_foreign' {
            $foreignDns=@($foreign|ForEach-Object dn);$findings=@($privilegedGroups|ForEach-Object{$g=$_;@([string]$g.member-split';'|Where-Object{$_-in$foreignDns})|ForEach-Object{[pscustomobject]@{Group=$g.dn;ForeignMember=$_}}})
            $source="$prefix\group.tsv; $prefix\foreignSecurityPrincipal.tsv";$explanation='Recherche des principals dʼune autre forêt dans les groupes privilégiés.'
        }
        'warning_privileged_members_no_adminsdholder' {
            $findings=@($privilegedAccounts|Where-Object{[string]$_.adminCount-ne'1'-and $_.objectSid-notmatch'-500$'}|Select-Object dn,sAMAccountName,adminCount)
            $source="$prefix\user.tsv; $prefix\computer.tsv";$explanation='Recherche les membres privilégiés non marqués comme protégés par AdminSDHolder.'
        }
        'warning_privileged_members_not_empty' {
            $findings=@($privilegedGroups|Where-Object{$_.member}|Select-Object dn,sAMAccountName,member)
            $source="$prefix\group.tsv";$explanation='Inventorie les groupes privilégiés qui contiennent au moins un membre.'
        }
        'warning_reversible_password' {
            $findings=@($activeUsers|Where-Object{Test-UacFlag $_ 128}|Select-Object dn,sAMAccountName,userAccountControl)
            $source="$prefix\user.tsv";$explanation='Recherche les comptes autorisant le stockage réversible du mot de passe.'
        }
        'warning_rid500' {
            $limit=$now.AddDays(-30);$findings=@($users|Where-Object{$_.objectSid-match'-500$'-and $_.lastLogonTimestamp-and(Convert-OradadDate $_.lastLogonTimestamp)-ge$limit}|Select-Object dn,sAMAccountName,lastLogonTimestamp)
            $source="$prefix\user.tsv";$explanation='Vérifie si le compte Administrateur intégré RID 500 a été utilisé récemment.'
        }
        'warning_schema_posssuperiors' {
            $findings=@($Dataset.Cache['schema\class.tsv']|Where-Object{$_.possSuperiors}|Select-Object dn,lDAPDisplayName,possSuperiors)
            $source='schema\class.tsv';$explanation='Liste les classes de schéma auxquelles des parents de création supplémentaires ont été ajoutés.'
        }
        'warning_sd_anonymous_control' {
            $findings=@($acl.Relations|Where-Object{$_.SourceSid-eq'S-1-5-7'-and $_.Right-notmatch'^(Read|List)'}|Select-Object SourceSid,TargetDn,Right,Inherited)
            $source='nTSecurityDescriptor';$explanation='Recherche des permissions de contrôle accordées à Everyone ou Anonymous Logon.'
        }
        'warning_sd_generic_perm' {
            $findings=@($acl.Relations|Where-Object{$_.Right-match'^Generic'}|Select-Object SourceSid,SourceDn,TargetDn,Right,Inherited)
            $source='nTSecurityDescriptor';$explanation='Inventorie les droits génériques présents dans les ACL.'
        }
        'warning_sd_repl_perm' {
            $findings=@($acl.Relations|Where-Object{$_.Right-match'DSInstallReplica|ReplicationManageTopology'}|Select-Object SourceSid,SourceDn,TargetDn,Right,Inherited)
            $source='nTSecurityDescriptor';$explanation='Recherche les permissions sensibles de gestion de la réplication.'
        }
        'warning_sd_unknown_sid' {
            $findings=@($acl.Relations|Where-Object{$_.SourceSid -and -not $_.SourceDn -and -not (Test-ADSOpenWellKnownSid ([string]$_.SourceSid))}|Select-Object SourceSid,TargetDn,Right,Inherited)
            $source='nTSecurityDescriptor';$explanation='Inventorie les ACE dont le SID source ne peut pas être résolu.'
        }
        'warning_spn_priv' {
            $findings=@($privilegedAccounts|Where-Object{$_.servicePrincipalName}|Select-Object dn,sAMAccountName,servicePrincipalName)
            $source="$prefix\user.tsv";$explanation='Liste les comptes privilégiés portant un SPN dans les cas tolérés mais à surveiller.'
        }
        'warning_sysvol_files_acl' {
            $findings=@($sysvol|Where-Object{$_.securitydescriptor-and$_.securitydescriptor-match'\(A;(?!(?:[^;]*ID))'}|Select-Object path,filename,securitydescriptor)
            $source="$prefix\sysvol.tsv";$explanation='Inventorie les ACE explicites présentes sur les fichiers de GPO.'
        }
        'warning_sysvol_files_sd' {
            $available='DataUnavailable';$source="$prefix\sysvol.tsv et référentiel de descripteurs par défaut";$explanation='Compare les options des descripteurs de sécurité des fichiers de GPO à leur valeur attendue.'
        }
        'warning_sysvol_no_repl' {
            $dfsr=@($Dataset.Schemas.Keys|Where-Object{$_-match'(?i)dfsr'});if(-not$ntfrs.Count-and-not$dfsr.Count){$findings=@([pscustomobject]@{Reason='Aucun objet NTFRS ou DFSR collecté'})}
            $source='tables NTFRS/DFSR';$explanation='Vérifie quʼun mécanisme de réplication SYSVOL est défini.'
        }
        'warning_sysvol_root_sd' {
            $available='DataUnavailable';$source="$prefix\sysvol.tsv et référentiel de descripteurs par défaut";$explanation='Compare les descripteurs des répertoires racines de GPO à leur valeur attendue.'
        }
        'warning_trusts_tgt_deleg' {
            $findings=@($tgtDeleg);$source="$prefix\trustedDomain.tsv";$explanation='Recherche les approbations entrantes autorisant la délégation TGT.'
        }
        'warning_user_accounts_dormant' {
            $dormant=Select-RecentOrDormant $users 90;$threshold=[math]::Max(20,[math]::Ceiling($activeUsers.Count*.1));if($dormant.Count-gt$threshold){$findings=@([pscustomobject]@{DormantCount=$dormant.Count;Threshold=$threshold;ActiveUsers=$activeUsers.Count})}
            $source="$prefix\user.tsv";$explanation='Signale une proportion importante de comptes actifs mais inactifs.'
        }
        default {
            $available='DataUnavailable';$source='Donnée ORADAD ou référentiel de comparaison requis'
        }
    }
    $advisoryResults.Add((New-AdvisoryResult $item $findings $explanation $recommendation $source $available))
}
Set-StrictMode -Version 2.0
@($advisoryResults)
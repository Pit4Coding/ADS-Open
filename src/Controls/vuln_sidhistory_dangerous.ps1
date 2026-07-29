param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')

if ($Mode -eq 'Definition') {
    return [pscustomobject]@{
        Id = 'vuln_sidhistory_dangerous'
        Levels = [int[]]@(2)
        Title = 'Comptes ou groupes ayant un historique de SID d''apparence non conforme'
    }
}

$dangerousSidHistory = @($users+$computers+$groups | ForEach-Object {
    $o=$_
    Split-MultiValue $_.sIDHistory | Where-Object {
        $sid=[string]$_
        $wellKnown = $sid -in @('S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-32-544',
            'S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551',
            'S-1-5-32-552')
        $privilegedRid = ($sid -split '-')[-1] -in @('500','502','512','516','518','519','521')
        $wellKnown -or $privilegedRid
    } | ForEach-Object { [pscustomobject]@{Dn=$o.dn;SidHistory=$_} }
})
Add-RemainingControl 'vuln_sidhistory_dangerous' @(2) `
    'SIDHistory dangereux' $dangerousSidHistory `
    'Supprimer les SID privilégiés ou bien connus de SIDHistory.' `
    "$prefix\user.tsv; $prefix\computer.tsv; $prefix\group.tsv"

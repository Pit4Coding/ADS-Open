param([ValidateSet('Definition','Evaluate')][string]$Mode = 'Definition')
if ($Mode -eq 'Definition') {
    return [pscustomobject]@{ Id='vuln_critical_objects'; Levels=[int[]]@(1); Title='Objets critiques non disponibles' }
}
$criticalParseErrors = @($acl.ParseErrors | Where-Object Dn -in $tier0Dns)
$results.Add((New-ControlResult 'vuln_critical_objects' @(1) 'Objets critiques non disponibles' `
    $(if ($criticalParseErrors.Count) { 'Failed' } else { 'Passed' }) $criticalParseErrors `
    'Rétablir la lisibilité et la disponibilité des objets critiques.' `
    'nTSecurityDescriptor (objets Tier 0)' 'Implemented'))

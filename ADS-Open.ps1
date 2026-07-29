[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputPath,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'output'),

    [ValidateSet('Html', 'Json', 'Both')]
    [string]$Format = 'Both'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\ADSOpen.psm1') -Force

Invoke-ADSOpenAudit -InputPath $InputPath -OutputPath $OutputPath -Format $Format

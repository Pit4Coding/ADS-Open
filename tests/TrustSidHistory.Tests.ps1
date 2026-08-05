$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $project 'src\ADSOpen.psm1') -Force
$module = Get-Module ADSOpen

function Test-Trust([int64]$Attributes, [int64]$Direction = 2) {
    $trust = [pscustomobject]@{
        trustAttributes_int = [string]$Attributes
        trustDirection_int = [string]$Direction
    }
    & $module { param($Value) Test-ForestTrustSidHistoryEnabled $Value } $trust
}

# Approbation de forêt sortante normale : FOREST_TRANSITIVE uniquement.
if (Test-Trust 0x8) {
    throw 'EnableSIDHistory:No ne doit pas être signalé'
}

# netdom /EnableSIDHistory:Yes ajoute TREAT_AS_EXTERNAL (0x40).
if (-not (Test-Trust (0x8 -bor 0x40))) {
    throw 'EnableSIDHistory:Yes doit être signalé'
}

# Le bit ne doit pas être interprété sur une approbation entrante uniquement.
if (Test-Trust (0x8 -bor 0x40) 1) {
    throw 'Une approbation entrante ne doit pas être signalée par ce contrôle'
}

# QUARANTINED_DOMAIN est indépendant d'EnableSIDHistory.
if (Test-Trust (0x8 -bor 0x4)) {
    throw 'Le bit QUARANTINED_DOMAIN ne doit pas être confondu avec EnableSIDHistory'
}

'OK - détection EnableSIDHistory sur les approbations de forêt'

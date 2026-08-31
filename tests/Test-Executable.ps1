[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ExecutablePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$exe = [IO.Path]::GetFullPath($ExecutablePath)
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "Executable does not exist: $exe"
}

$unicodeName = ([string][char]0x79D2) + ([char]0x6740) + ([char]0x5C0F) + ([char]0x54C8)
$systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$testRoot = Join-Path $systemTemp ($unicodeName + ' EXE test ' + [Guid]::NewGuid().ToString('N'))
$target = Join-Path $testRoot 'server data'
$local = Join-Path $target 'resources\[local]'
$owned = Join-Path $local 'hgadmin'
$normal = Join-Path $local 'normal'
$utf8 = New-Object Text.UTF8Encoding($false)

try {
    New-Item -ItemType Directory -Path $owned, $normal -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $owned 'fxmanifest.lua'),
        "fx_version 'cerulean'`nauthor 'XIAOHA'`n",
        $utf8
    )
    [IO.File]::WriteAllText(
        (Join-Path $normal 'fxmanifest.lua'),
        "client_script 'hgadmin_guard.lua' -- [[HGADMIN-GUARD]]`nclient_script 'client.lua'`n",
        $utf8
    )
    [IO.File]::WriteAllText(
        (Join-Path $normal 'hgadmin_guard.lua'),
        '-- [[HGADMIN-GUARD]] HGAdmin guard' + [Environment]::NewLine,
        $utf8
    )
    [IO.File]::WriteAllText(
        (Join-Path $normal 'client.lua'),
        "print('keep')`n",
        $utf8
    )
    [IO.File]::WriteAllText(
        (Join-Path $target 'server.cfg'),
        "ensure hgadmin`nensure normal`n",
        $utf8
    )
    $preservedHash = (Get-FileHash -LiteralPath (Join-Path $normal 'client.lua') -Algorithm SHA256).Hash

    $scanOutput = Join-Path $testRoot ($unicodeName + ' scan report')
    & $exe scan $target --output $scanOutput
    if ($LASTEXITCODE -ne 0) { throw "Executable scan failed: $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $owned -PathType Container)) {
        throw 'Read-only scan modified the owned resource.'
    }
    $scanReportPath = Join-Path $scanOutput 'scan-report.json'
    $scan = Get-Content -LiteralPath $scanReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        [string]$scan.status -cne 'scan' -or
        [int]$scan.summary.owned_resources -ne 1 -or
        [int]$scan.summary.injection_files -ne 1 -or
        -not [bool]$scan.terminal
    ) {
        throw 'Executable scan report did not contain the expected terminal result.'
    }

    $quarantine = Join-Path $testRoot ($unicodeName + ' quarantine')
    & $exe clean $target --yes --quarantine-root $quarantine
    if ($LASTEXITCODE -ne 0) { throw "Executable clean failed: $LASTEXITCODE" }
    $runReports = @(Get-ChildItem -LiteralPath $quarantine -Filter 'run-report.json' -File -Recurse)
    if ($runReports.Count -ne 1) {
        throw "Expected one run report, found $($runReports.Count)."
    }
    $runReport = Get-Content -LiteralPath $runReports[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$runReport.status -cne 'cleaned' -or -not [bool]$runReport.terminal) {
        throw 'Executable clean report did not contain the expected terminal result.'
    }
    if (Test-Path -LiteralPath $owned) {
        throw 'Executable clean did not quarantine the owned resource.'
    }

    & $exe restore $runReports[0].FullName --yes
    if ($LASTEXITCODE -ne 0) { throw "Executable restore failed: $LASTEXITCODE" }
    if (
        -not (Test-Path -LiteralPath $owned -PathType Container) -or
        -not (Test-Path -LiteralPath (Join-Path $normal 'hgadmin_guard.lua') -PathType Leaf)
    ) {
        throw 'Executable restore did not restore quarantined files.'
    }
    $restoredHash = (Get-FileHash -LiteralPath (Join-Path $normal 'client.lua') -Algorithm SHA256).Hash
    if ($restoredHash -cne $preservedHash) {
        throw 'Executable restore changed a preserved file.'
    }
    $restoreReportPath = Join-Path $runReports[0].DirectoryName 'restore-report.json'
    $restoreReport = Get-Content -LiteralPath $restoreReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$restoreReport.status -cne 'restored' -or -not [bool]$restoreReport.terminal) {
        throw 'Executable restore report did not contain the expected terminal result.'
    }

    [pscustomobject]@{
        executable = $exe
        unicodePath = $true
        scanStatus = [string]$scan.status
        cleanStatus = [string]$runReport.status
        restoreStatus = [string]$restoreReport.status
        restoredHashMatches = ($restoredHash -ceq $preservedHash)
    } | ConvertTo-Json -Compress
} finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot).TrimEnd('\')
    if (-not $resolvedTestRoot.StartsWith($systemTemp + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe executable test cleanup path: $resolvedTestRoot"
    }
    if (Test-Path -LiteralPath $resolvedTestRoot) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}

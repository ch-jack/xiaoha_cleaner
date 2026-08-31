[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$OutputDirectory = '',
    [string]$ExecutablePath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $Version) {
    $Version = [IO.File]::ReadAllText((Join-Path $root 'VERSION')).Trim()
}
if ($Version -notmatch '^v\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.-]+)?$') {
    throw "Invalid version: $Version"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root 'dist'
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null

$packageName = "xiaoha-cleaner-$Version"
$stage = Join-Path $output $packageName
$asset = Join-Path $output ("$packageName-windows.zip")
$checksum = "$asset.sha256"

foreach ($path in @($stage, $asset, $checksum)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$releaseFiles = @(
    'xiaoha-cleaner.py',
    'xiaoha-cleaner.cmd',
    'xiaoha_cleaner.py',
    'xiaoha_cleaner_all_sql.py',
    'XiaohaCleaner.py',
    'XiaohaCleanerFinal.py',
    'XiaohaCleanerAuto.py',
    'XiaohaCleanerGui.py',
    'README.md',
    'SECURITY.md',
    'CHANGELOG.md',
    'LICENSE',
    'VERSION',
    'component-manifest.json'
)
foreach ($file in $releaseFiles) {
    $source = Join-Path $root $file
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing release file: $file"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $file)
}

if (-not $ExecutablePath) {
    $ExecutablePath = Join-Path $output "xiaoha-cleaner-$Version-windows-x64.exe"
}
$ExecutablePath = [IO.Path]::GetFullPath($ExecutablePath)
if (-not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
    throw "Missing standalone executable: $ExecutablePath"
}
Copy-Item -LiteralPath $ExecutablePath -Destination (Join-Path $stage 'xiaoha-cleaner.exe')

[IO.File]::WriteAllText(
    (Join-Path $stage 'VERSION'),
    "$Version`n",
    (New-Object Text.UTF8Encoding($false))
)
$manifestPath = Join-Path $stage 'component-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$manifest.version = $Version
[IO.File]::WriteAllText(
    $manifestPath,
    ($manifest | ConvertTo-Json -Depth 8),
    (New-Object Text.UTF8Encoding($false))
)

$forbidden = Get-ChildItem -LiteralPath $stage -Recurse -Force | Where-Object {
    $_.Name -in @('server.cfg', '__pycache__', '_xiaoha_quarantine') -or
    $_.Name -like '*.sql' -or
    $_.Name -like '*scan-report*' -or
    $_.Name -like '*run-report*' -or
    $_.Name -like '*.zip' -or
    ($_.PSIsContainer -and $_.Name -in @('build', 'dist'))
}
if ($forbidden) {
    throw "Forbidden release content: $($forbidden.FullName -join ', ')"
}
$credentialPattern = '(?i)mysql://[^\s"'']+:[^\s"'']+@|mysql_connection_string\s+["''][^"'']+["'']'
$credentialHits = Get-ChildItem -LiteralPath $stage -Recurse -File |
    Where-Object { $_.Extension -in @('.cfg', '.ini') } |
    Select-String -Pattern $credentialPattern
if ($credentialHits) {
    throw 'Credential-like configuration was found in the release stage.'
}

Compress-Archive -LiteralPath $stage -DestinationPath $asset -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(
    $checksum,
    "$hash  $([IO.Path]::GetFileName($asset))`n",
    (New-Object Text.ASCIIEncoding)
)

[pscustomobject]@{
    version = $Version
    package = $stage
    asset = $asset
    checksum = $checksum
    sha256 = $hash
} | ConvertTo-Json -Compress

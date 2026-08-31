[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$OutputDirectory = '',
    [string]$PythonCommand = 'python'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $Version) {
    $Version = [IO.File]::ReadAllText((Join-Path $root 'VERSION')).Trim()
}
if ($Version -notmatch '^v(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:[-.][A-Za-z0-9.-]+)?$') {
    throw "Invalid version: $Version"
}
$numericVersion = "$($Matches.major).$($Matches.minor).$($Matches.patch)"
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root 'dist'
}
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
New-Item -ItemType Directory -Path $output -Force | Out-Null

function Assert-ChildPath {
    param([string]$Path, [string]$Parent)
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    if (-not $fullPath.StartsWith($fullParent + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Build path escaped output directory: $fullPath"
    }
    return $fullPath
}

$assetName = "xiaoha-cleaner-$Version-windows-x64.exe"
$asset = Join-Path $output $assetName
$checksum = "$asset.sha256"
$buildRoot = Assert-ChildPath -Path (Join-Path $output ('.pyinstaller-' + [Guid]::NewGuid().ToString('N'))) -Parent $output
$pyInstallerDist = Join-Path $buildRoot 'dist'
$pyInstallerWork = Join-Path $buildRoot 'work'
$pyInstallerSpec = Join-Path $buildRoot 'spec'
$versionInfo = Join-Path $buildRoot 'version-info.txt'

foreach ($path in @($asset, $checksum)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force
    }
}
New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null

$versionResource = @"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=($($Matches.major), $($Matches.minor), $($Matches.patch), 0),
    prodvers=($($Matches.major), $($Matches.minor), $($Matches.patch), 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '080404B0',
        [StringStruct('CompanyName', 'CK'),
         StringStruct('FileDescription', '秒杀小哈'),
         StringStruct('FileVersion', '$numericVersion'),
         StringStruct('InternalName', 'xiaoha-cleaner'),
         StringStruct('LegalCopyright', 'MIT License'),
         StringStruct('OriginalFilename', 'xiaoha-cleaner.exe'),
         StringStruct('ProductName', '秒杀小哈'),
         StringStruct('ProductVersion', '$numericVersion')]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
"@
[IO.File]::WriteAllText($versionInfo, $versionResource, (New-Object Text.UTF8Encoding($false)))

try {
    Push-Location $root
    try {
        & $PythonCommand -m PyInstaller `
            --noconfirm `
            --clean `
            --onefile `
            --console `
            --name 'xiaoha-cleaner' `
            --version-file $versionInfo `
            --distpath $pyInstallerDist `
            --workpath $pyInstallerWork `
            --specpath $pyInstallerSpec `
            (Join-Path $root 'xiaoha-cleaner.py') 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "PyInstaller exited with code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    $builtExe = Join-Path $pyInstallerDist 'xiaoha-cleaner.exe'
    if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
        throw "PyInstaller output is missing: $builtExe"
    }
    Copy-Item -LiteralPath $builtExe -Destination $asset -Force

    $reportedVersion = & $asset --version
    if ($LASTEXITCODE -ne 0 -or $reportedVersion.Trim() -ne $numericVersion) {
        throw "Executable version mismatch: $reportedVersion"
    }
    & $asset --gui-smoke-test | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Executable GUI smoke test failed: $LASTEXITCODE"
    }

    $hash = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $checksum,
        "$hash  $assetName`n",
        (New-Object Text.ASCIIEncoding)
    )
} finally {
    if (Test-Path -LiteralPath $buildRoot) {
        $safeBuildRoot = Assert-ChildPath -Path $buildRoot -Parent $output
        Remove-Item -LiteralPath $safeBuildRoot -Recurse -Force
    }
}

[pscustomobject]@{
    version = $Version
    executable = $asset
    checksum = $checksum
    sha256 = (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
    size = (Get-Item -LiteralPath $asset).Length
} | ConvertTo-Json -Compress

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
$version = '1.2.0'
$chocoVersion = '1.2.0-r3'
$packageName = 'zstd'
$projectSource = 'https://github.com/facebook/zstd'
$packageSourceUrl = 'https://github.com/facebook/zstd'
$authors = 'Facebook'
$owners = 'Facebook'
$copyright = 'https://github.com/facebook/zstd/blob/master/LICENSE'
$license = 'https://github.com/facebook/zstd/blob/master/LICENSE'
$url = "https://github.com/facebook/zstd/archive/v$version.zip"

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Save loc for restoring later
$currentLoc = Get-Location

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Create the choco build dir if needed
$buildPath = Get-OsqueryBuildPath
if ($buildPath -eq '') {
  Write-Host '[-] Failed to find source root' -foregroundcolor red
  exit
}
$chocoBuildPath = "$buildPath\chocolatey\$packageName"
if (-not (Test-Path "$chocoBuildPath")) {
  New-Item -Force -ItemType Directory -Path "$chocoBuildPath"
}
Set-Location $chocoBuildPath

# Retrieve the source
$zipFile = "$packageName-$version.zip"
if(-not (Test-Path $zipFile)) {
  Invoke-WebRequest $url -OutFile $zipFile
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "$packageName-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $arg = "x $zipFile"
  Start-Process -FilePath $7z -ArgumentList $arg -NoNewWindow -Wait
}
Set-Location $sourceDir


# Configure and build the libraries
$envArch = [System.Environment]::GetEnvironmentVariable('OSQ32')
$arch = ''
$platform = ''
$cmakeBuildType = ''
if ($envArch -eq 1) {
  $arch = 'Win32'
  $platform = 'x86'
} else {
  $arch = 'x64'
  $platform = 'amd64'
}

Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" $platform

$vcxprojLocation = Join-Path $(Get-Location) 'build\VS2010\libzstd\libzstd.vcxproj'
# Patch the AssemblerOutput out of the project
Move-Item -Force $vcxprojLocation "$vcxprojLocation.bak"
$old = '<AssemblerOutput>All</AssemblerOutput>'
$new = '<AssemblerOutput>NoListing</AssemblerOutput>'
(Get-Content "$vcxprojLocation.bak").replace($old, $new) |
  Set-Content $vcxprojLocation

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$configs = @('Release', 'Debug')
foreach ($cfg in $configs) {
  $msbuildArgs = @(
    'build\VS2010\zstd.sln',
    "/p:Configuration=$cfg",
    "/p:PlatformType=$arch",
    "/p:Platform=$arch",
    '/p:PlatformToolset=v140',
    '/t:Clean,libzstd',
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs
}

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'

Write-NuSpec `
  $packageName `
  $chocoVersion `
  $authors `
  $owners `
  $projectSource `
  $packageSourceUrl `
  $copyright `
  $license

Set-Location $sourceDir
$relLibPath = "build\VS2010\bin\$arch" + '_Release\libzstd_static.lib'
$debLibPath = "build\VS2010\bin\$arch" + '_Debug\libzstd_static.lib'
Copy-Item  $relLibPath $libDir
Copy-Item $debLibPath "$libDir\libzstd_static_dbg.lib"
Copy-Item -Recurse "lib\zstd.h" $includeDir
Copy-Item $buildScript $srcDir
Set-Location 'osquery-choco'
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" `
  -ForegroundColor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  $package = "$(Get-Location)\$packageName.$chocoVersion.nupkg"
  Write-Host `
    "[+] Finished building. Package written to $package" -ForegroundColor Green
} else {
  Write-Host `
    "[-] Failed to build $packageName v$chocoVersion." `
    -ForegroundColor Red
}
Set-Location $currentLoc

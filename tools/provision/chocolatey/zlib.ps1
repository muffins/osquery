#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Update-able metadata
#
# $version - The version of the software package to build
# $chocoVersion - The chocolatey package version, used for incremental bumps
#                 without changing the version of the software package

$version = '1.2.11'
$chocoVersion = $version
$packageName = 'zlib'
$projectSource = 'http://zlib.net'
$packageSourceUrl = 'http://zlib.net'
$authors = 'Jean-loup Gailly and Mark Adler'
$owners = 'Jean-loup Gailly and Mark Adler'
$copyright = 'Copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler'
$license = 'http://zlib.net/zlib_license.html'
$url="http://zlib.net/zlib-$version.tar.gz"

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Keep track of our location to restore later
$currentLoc = Get-Location

# Create the choco build dir if needed
$buildPath = Get-OsqueryBuildPath
if ($buildPath -eq '') {
  Write-Host '[-] Failed to find source root' -ForegroundColor red
  exit
}
$chocoBuildPath = "$buildPath\chocolatey\$packageName"
if (-not (Test-Path "$chocoBuildPath")) {
  New-Item -Force -ItemType Directory -Path "$chocoBuildPath"
}
Set-Location $chocoBuildPath

# Retreive the source
if (-not (Test-Path "zlib-$version.tgz")) {
  Invoke-WebRequest $url -OutFile "zlib-$version.tgz" `
    -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
}

$sourceDir = Join-Path $(Get-Location) "$packageName-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x zlib-$version.tgz"
  Start-OsqueryProcess $7z $7zargs
  $7zargs = "x zlib-$version.tar"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Build the libraries, remove any old versions first.
$buildDir = Join-Path $(Get-Location) 'osquery-win-build'
if(Test-Path $buildDir){
  Remove-Item -Force -Recurse $buildDir
}
New-Item -Force -ItemType Directory -Path $buildDir
Set-Location $buildDir

# Configure and build the libraries
$envArch = [System.Environment]::GetEnvironmentVariable('OSQ32')
$arch = ''
$platform = ''
$cmakeBuildType = ''
if ($envArch -eq 1) {
  $cmakeBuildType = 'Visual Studio 14 2015'
  $arch = 'Win32'
  $platform = 'x86'
} else {
  $cmakeBuildType = 'Visual Studio 14 2015 Win64'
  $arch = 'x64'
  $platform = 'amd64'
}

Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" $platform

$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  "-G `"$cmakeBuildType`"",
  '..\'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$configs = @('Release', 'Debug')
foreach ($cfg in $configs) {
  $msbuildArgs = @(
    'zlib.sln',
    "/p:Configuration=$cfg",
    "/p:PlatformType=$arch",
    "/p:Platform=$arch",
    '/t:zlib',
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs
  $msbuildArgs = @(
    'zlib.sln',
    "/p:Configuration=$cfg",
    "/p:PlatformType=$arch",
    "/p:Platform=$arch",
    '/t:zlibstatic',
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs
}

# If the build path exists, purge it for a clean packaging
$chocoDir = Join-Path $(Get-Location) 'osquery-choco'
if (Test-Path $chocoDir) {
  Remove-Item -Force -Recurse $chocoDir
}

# Construct the Chocolatey Package
New-Item -ItemType Directory -Path $chocoDir
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

# Rename the Debug libraries to end with a `_dbg.lib`
Copy-Item "$buildDir\Release\zlibstatic.lib" $libDir
Copy-Item "$buildDir\Debug\zlibstaticd.lib" "$libDir\zlibstatic_dbg.lib"
Copy-Item "$buildDir\zconf.h" $includeDir
Copy-Item "$buildDir\..\zlib.h" $includeDir
Copy-Item $buildScript $srcDir
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

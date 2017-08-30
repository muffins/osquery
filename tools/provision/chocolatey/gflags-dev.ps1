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
$version = '2.2.0'
$chocoVersion = '2.2.0'
$packageName = 'gflags-dev'
$projectSource = 'https://github.com/gflags/gflags'
$packageSourceUrl = 'https://github.com/gflags/gflags'
$authors = 'google'
$owners = 'google'
$copyright = 'https://github.com/gflags/gflags/blob/master/COPYING.txt'
$license = 'https://github.com/gflags/gflags/blob/master/COPYING.txt'
$url = "https://github.com/gflags/gflags/archive/v$version.zip"

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Keep track of our location to restore later
$currentLoc = Get-Location

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

# Retreive the source
if (-not (Test-Path "gflags-$version.zip")) {
  Invoke-WebRequest $url -OutFile "gflags-$version.zip" `
    -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
}

$sourceDir = Join-Path $(Get-Location) "gflags-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x gflags-$version.zip"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Set the cmake logic to generate a static build for us
$staticBuildFlags = "`nset(CMAKE_CXX_FLAGS_RELEASE `"`${CMAKE_CXX_FLAGS_RELEASE} " +
"/MT`")`nset(CMAKE_CXX_FLAGS_DEBUG `"`${CMAKE_CXX_FLAGS_DEBUG} /MTd`")"
Add-Content `
  -NoNewline `
  -Path $(Join-Path $sourceDir 'CMakeLists.txt') `
  -Value $staticBuildFlags

# Build the libraries
$buildDir = New-Item -Force -ItemType Directory -Path "osquery-win-build"
Set-Location $buildDir

# Generate the solution files
$envArch = [System.Environment]::GetEnvironmentVariable('OSQ32')
$arch = ''
$cmakeBuildType = ''
if ($envArch -eq 1) {
  $arch = 'Win32'
  $cmakeBuildType = 'Visual Studio 14 2015'
} else {
  $arch = 'x64'
  $cmakeBuildType = 'Visual Studio 14 2015 Win64'
}
Move-Item -Force $PROFILE "$PROFILE.bak"
$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  "-G `"$cmakeBuildType`"",
  '-DGFLAGS_BUILD_STATIC_LIBS=ON',
  '-DGFLAGS_BUILD_SHARED_LIBS=OFF',
  '-DGFLAGS_BUILD_gflags_LIB=ON',
  '-DGFLAGS_NAMESPACE=google',
  '../'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$sln = 'gflags.sln'
$configurations = @(
  'Release',
  'Debug'
)
foreach ($cfg in $configurations) {
  $msbuildArgs = @(
    "$sln",
    "/p:Configuration=$cfg",
    "/p:PlatformType=$arch",
    "/p:Platform=$arch",
    '/t:gflags_static',
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs
}

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path "osquery-choco"
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path "local\include"
$libDir = New-Item -ItemType Directory -Path "local\lib"
$srcDir = New-Item -ItemType Directory -Path "local\src"

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
foreach ($lib in Get-ChildItem "$buildDir\lib\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item -Path $lib.Fullname -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\lib\Release\*" $libDir
Copy-Item -Recurse "$buildDir\include\gflags" $includeDir
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

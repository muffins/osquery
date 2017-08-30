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
$version = '0.3.4'
$chocoVersion = '0.3.4'
$packageName = 'glog'
$projectSource = 'https://github.com/google/glog'
$packageSourceUrl = 'https://github.com/google/glog'
$authors = 'google'
$owners = 'google'
$copyright = 'https://github.com/google/glog/blob/master/COPYING'
$license = 'https://github.com/google/glog/blob/master/COPYING'
$url = 'https://github.com/google/glog.git'

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
  Write-Host '[-] Failed to find source root' -foregroundcolor red
  exit
}
$chocoBuildPath = "$buildPath\chocolatey\$packageName"
if (-not (Test-Path "$chocoBuildPath")) {
  New-Item -Force -ItemType Directory -Path "$chocoBuildPath"
}
Set-Location $chocoBuildPath

# we currently just use master.
$sourceDir = Join-Path $(Get-Location) 'glog'
$git = (Get-Command 'git').Source
$gitArgs = "clone $url"
Start-OsqueryProcess $git $gitArgs
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
$platform = ''
$cmakeBuildType = ''
if ($envArch -eq 1) {
  $arch = 'Win32'
  $platform = 'x86'
  $cmakeBuildType = 'Visual Studio 14 2015'
} else {
  $arch = 'x64'
  $platform = 'amd64'
  $cmakeBuildType = 'Visual Studio 14 2015 Win64'
}

Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" $platform

$cmake = (Get-Command 'cmake').Source
$cmakeArgs = @(
  "-G `"$cmakeBuildType`"",
  '-DCMAKE_PREFIX_PATH=C:\ProgramData\chocolatey\lib\gflags\local\lib\',
  '../'
)
Start-OsqueryProcess $cmake $cmakeArgs

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$sln = 'glog.sln'
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
    '/t:glog',
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
foreach ($lib in Get-ChildItem "$buildDir\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item -Path $lib.Fullname -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\Release\*" $libDir
Copy-Item -Recurse "$buildDir\..\src\windows\glog" $includeDir
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

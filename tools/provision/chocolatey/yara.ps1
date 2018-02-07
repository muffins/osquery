#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

$chocoVersion = '3.5.0'
$packageName = 'yara'
$projectSource = 'https://github.com/VirusTotal/yara'
$packageSourceUrl = "https://github.com/VirusTotal/yara/releases/tag/v$chocoVersion"
$authors = 'https://github.com/VirusTotal/yara/blob/master/AUTHORS'
$owners = 'https://github.com/VirusTotal/yara/blob/master/AUTHORS'
$copyright = 'https://github.com/VirusTotal/yara/blob/master/COPYING'
$license = 'https://github.com/VirusTotal/yara/blob/master/COPYING'
$url = "https://github.com/VirusTotal/yara/archive/v$chocoVersion.zip"

$loc = Get-Location

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

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

# Retreive the source only if it doesn't already exist
if (-not (Test-Path "$packageName-$chocoVersion.zip")) {
  Invoke-WebRequest `
    -OutFile "$packageName-$chocoVersion.zip" `
    -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome `
    $url
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "$packageName-$chocoVersion"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x $packageName-$chocoVersion.zip"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# Check for pre-req packages before continuing
if ($(Get-Command 'vswhere' -ErrorAction SilentlyContinue) -eq $null) {
  $msg = '[-] Did not find vswhere in PATH. Please re-provision.'
  Write-Host $msg -foregroundcolor red
  exit
}

$nuget = $(Get-Command 'nuget' -ErrorAction SilentlyContinue)
if ($nuget -eq $null) {
  $msg = '[-] Did not find NuGet in PATH. Please re-provision.'
  Write-Host $msg -foregroundcolor red
  exit
}

# Build the libraries
$buildDir = "$sourceDir\windows\vs2015"
Set-Location $buildDir

$nugetArgs = @(
  'restore',
  'yara.sln'
)
Start-OsqueryProcess $nuget $nugetArgs $false

# Build the libraries
$msbuild = (Get-Command 'msbuild').Source
$configurations = @('Release', 'Debug')

foreach($cfg in $configurations) {
  $msbuildArgs = @(
    'yara.sln',
    "/p:Configuration=$cfg",
    '/t:libyara',
    '/m',
    '/v:m'
  )
  Start-OsqueryProcess $msbuild $msbuildArgs $false
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
$binDir = New-Item -ItemType Directory -Path 'local\bin'
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
foreach ($lib in Get-ChildItem "$buildDir\libyara\Debug\") {
  $toks = $lib.Name.split('.')
  $newLibName = $toks[0..$($toks.count - 2)] -join '.'
  $suffix = $toks[$($toks.count - 1)]
  Copy-Item `
    -Path $lib.Fullname `
    -Destination "$libDir\$newLibName`_dbg.$suffix"
}
Copy-Item "$buildDir\libyara\Release\*" $libDir
Copy-Item -Recurse "$sourceDir\libyara\include\*" $includeDir
Copy-Item $buildScript $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" `
  -ForegroundColor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  $pkgPath = Join-Path $(Get-Location) "$packageName.$chocoVersion.nupkg"
  $msg = "[+] Finished building $packageName v$chocoVersion. " +
         "Package written to $pkgPath"
  Write-Host $msg -ForegroundColor Green
}
else {
  $msg = "[-] Failed to build $packageName v$chocoVersion."
  Write-Host $msg -ForegroundColor Red
}
Set-Location $loc

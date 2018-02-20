#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# For more information -
# https://studiofreya.com/2016/09/29/how-to-build-boost-1-62-with-visual-studio-2015/
# Update-able metadata
#
# $version - The version of the software package to build
# $chocoVersion - The chocolatey package version, used for incremental bumps
#                 without changing the version of the software package
$version = '1.13'
$chocoVersion = '1.13'
$packageName = 'rapidxml'
$projectSource = 'http://rapidxml.sourceforge.net/'
$packageSourceUrl = 'http://rapidxml.sourceforge.net/'
$authors = 'Marcin Kalicinski'
$owners = 'Marcin Kalicinski'
$copyright = 'http://rapidxml.sourceforge.net/license.txt'
$license = 'http://rapidxml.sourceforge.net/license.txt'
$timestamp = [int][double]::Parse((Get-Date -UFormat %s))
$url = 'https://downloads.sourceforge.net/project/rapidxml/rapidxml/' +
       "rapidxml%20$version/rapidxml-$version.zip?ts=$timestamp"
$numJobs = 2

$currentLoc = Get-Location

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

# Invoke the MSVC developer tools/env
Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScriptSource = $MyInvocation.MyCommand.Definition

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
if (-not (Test-Path "rapidxml-$version.zip")) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest `
    -OutFile "rapidxml-$version.zip" `
    -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome `
    $url
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "rapidxml-$version"
if (-not (Test-Path $sourceDir)) {
  $7z = (Get-Command '7z').Source
  $7zargs = "x rapidxml-$version.zip"
  Start-OsqueryProcess $7z $7zargs
}
Set-Location $sourceDir

# If the build path exists, purge it for a clean packaging
$chocoDir = Join-Path $(Get-Location) 'osquery-choco'
if (Test-Path $chocoDir) {
  Remove-Item -Force -Recurse $chocoDir
}

# Construct the Chocolatey Package
New-Item -ItemType Directory -Path $chocoDir
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
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

Copy-Item "$sourceDir\*" $includeDir
Copy-Item $buildScriptSource $srcDir
choco pack

Write-Host "[*] Build took $($sw.ElapsedMilliseconds) ms" `
  -ForegroundColor DarkGreen
if (Test-Path "$packageName.$chocoVersion.nupkg") {
  $package = "$(Get-Location)\$packageName.$chocoVersion.nupkg"
  Write-Host `
    "[+] Finished building. Package written to $package" -ForegroundColor Green
}
else {
  Write-Host `
    "[-] Failed to build $packageName v$chocoVersion." `
    -ForegroundColor Red
}
Set-Location $currentLoc

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
$version = '1_0_2k'
$chocoVersion = '1.0.2-k'
$packageName = 'openssl'
$projectSource = 'https://github.com/apache/thrift'
$packageSourceUrl = 'https://github.com/apache/thrift'
$authors = 'https://github.com/openssl/openssl/blob/master/AUTHORS'
$owners = 'The OpenSSL Project'
$copyright = 'https://github.com/openssl/openssl/blob/master/LICENSE'
$license = 'https://github.com/openssl/openssl/blob/master/LICENSE'
$url = "https://github.com/openssl/openssl/archive/OpenSSL_$version.zip"

# Public Cert bundle we bring alonge with openssl libs
$curlCerts = 'https://curl.haxx.se/ca/cacert-2017-06-07.pem'
$curlCertsShaSum =
  'E78C8AB7B4432BD466E64BB942D988F6C0AC91CD785017E465BDC96D42FE9DD0'

# Invoke our utilities file
. "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\osquery_utils.ps1"

$ucrt = 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.14393.0\ucrt'
if (-not(Test-Path $ucrt)) {
  $msg =  '[-] Did not find the Windows Universal C Runtime. Please add the ' +
          'path to UCRT to your system path, or install it from here: ' +
          'https://goo.gl/9meug1'
  Write-Host $msg -ForegroundColor Yellow
}

# Check that Perl is installed
if (-not (Get-Command 'perl' -ErrorAction SilentlyContinue)) {
  $msg = '[-] This build requires perl which was not found. Please install ' +
         'perl from http://www.activestate.com/activeperl/downloads and add ' +
         'to the SYSTEM path before continuing'
  Write-Host $msg -ForegroundColor Red
  exit
}

# Check that NASM is installed
if (-not (Get-Command 'nmake' -ErrorAction SilentlyContinue)) {
  $msg = '[-] This build requires Nmake which was not found. Please check ' +
         'your Windows UCRT installation'
  Write-Host $msg -ForegroundColor Red
  exit
}

# Check that NASM is installed
if (-not (Get-Command 'nasm' -ErrorAction SilentlyContinue)) {
  $msg = '[-] This build requires NASM which was not found. Please ' +
         're-run the developer environment provisioning script and add ' +
         '"C:\Program Files\NASM" to your system path before continuing.'
  Write-Host $msg -ForegroundColor Red
  exit
}

# Time our execution
$sw = [System.Diagnostics.StopWatch]::startnew()

# Keep the location of build script, to bring with in the chocolatey package
$buildScript = $MyInvocation.MyCommand.Definition

# Grab the location to restore it later
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
$zipFile = Join-Path $(Get-Location) "$packageName-$version.zip"
if (-not (Test-Path $zipFile)) {
  Invoke-WebRequest $url -OutFile "$zipFile"
}

# Extract the source
$sourceDir = Join-Path $(Get-Location) "$packageName-OpenSSL_$version"
7z x $zipFile
Set-Location $sourceDir

# Configure and build the libraries
$envArch = [System.Environment]::GetEnvironmentVariable('OSQ32')
$arch = ''
$platform = ''
$cmakeBuildType = ''
if ($envArch -eq 1) {
  $config = 'VC-WIN32'
  $platform = 'x86'
} else {
  $config = 'VC-WIN64A'
  $platform = 'x64'
}

Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" $platform

# Build the libraries
$perl = (Get-Command 'perl').Source
$perlArgs = @(
  'Configure',
  "$config"
)
Start-OsqueryProcess $perl $perlArgs
$bat = ''
if ($envArch -eq 1) {
  $bat = Join-Path $sourceDir 'ms\do_nasm.bat'
} else {
  $bat = Join-Path $sourceDir 'ms\do_win64a'
}
Invoke-BatchFile $bat
$nmake = (Get-Command 'nmake').Source
$mak = Join-Path $sourceDir 'ms\nt.mak'
$nmakeArgs = @(
  '-f',
  "$mak"
)
Start-OsqueryProcess $nmake $nmakeArgs

# Construct the Chocolatey Package
$chocoDir = New-Item -ItemType Directory -Path 'osquery-choco'
Set-Location $chocoDir
$includeDir = New-Item -ItemType Directory -Path 'local\include'
$libDir = New-Item -ItemType Directory -Path 'local\lib'
$srcDir = New-Item -ItemType Directory -Path 'local\src'
$certsDir = New-Item -ItemType Directory -Path 'local\certs'

Write-NuSpec `
  $packageName `
  $chocoVersion `
  $authors `
  $owners `
  $projectSource `
  $packageSourceUrl `
  $copyright `
  $license

# Copy the libs and headers to their correct location
Copy-Item "..\out32\ssleay32.lib" $libDir
Copy-Item "..\out32\libeay32.lib" $libDir
Copy-Item -Recurse "..\inc32\openssl" $includeDir

# Grab the OpenSSL Curl cert bundle
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest $curlCerts -Outfile "$certsDir\certs.pem"
$hash = (Get-FileHash -Algorithm sha256 "$certsDir\certs.pem").Hash
if (-not ($hash -eq $curlCertsShaSum)) {
  Write-Host "[-] Warning: certs.pem sha sum mismatch!" -foregroundcolor Yellow
}

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

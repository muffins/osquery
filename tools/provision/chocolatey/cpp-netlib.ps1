#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# TODO: Move these into the osquery_utils lib
$chocolateyRoot = "C:\ProgramData\chocolatey\lib"
$openSslDir = "$chocolateyRoot\openssl"
$openSslInclude = "$openSslDir\include"
$boostRoot = "$chocolateyRoot\boost-msvc14\local"
$boostLibRoot = "$boostRoot\lib64-msvc-14.0"
$env:OPENSSL_ROOT_DIR=$openSslDir
$env:BOOST_ROOT=$boostRoot
$env:BOOST_LIBRARYDIR=$boostLibRoot

function Download-File {
  param(
    [string] $url,
    [string] $outfile
  )
  Try {
    Write-Host "[+] Downloading $url"
    (New-Object System.Net.WebClient).DownloadFile($url, $outfile)
    Write-Host '[+] Done.'
  } catch [Net.WebException] {
    Write-Host "[-] ERROR: Download failed, check network connection" -foregroundcolor Red
    #Exit -1
  }
}

function Build-CppNetlib {
  param(
    [string] $buildDir = '',
    [string] $version = '',
    [boolean] $rel = 'Release'
  )
  #$version = ''
  #$url="https://github.com/cpp-netlib/cpp-netlib/archive/cpp-netlib-$version.zip"
  # TODO: Abstract :P
  $version = '0.12.0-final'
  $url = "https://github.com/cpp-netlib/cpp-netlib/archive/cpp-netlib-$version.zip"

  # TODO: Do we need sed?
  # TODO: Do we need a check for git here?
  #       - No? I think we'll download the zip and go from there.
  # TODO: Check for cmake
  $oldLocation = Get-Location
  Set-Location $buildDir

  Download-File $url (Join-Path $buildDir 'cpp-netlib.zip')
  7z x -ocpp-netlib 'cpp-netlib.zip'
  Set-Location 'cpp-netlib'
  $sourceDir = Join-Path $(Get-Location) "cpp-netlib-cpp-netlib-$version"
  New-Item -ItemType Directory -Path '.\windows-build'
  Set-Location '.\windows-build'
  $params = "-G 'Visual Studio 14 2015 Win64' "`
        + '-DCPP-NETLIB_BUILD_TESTS=OFF '`
        + '-DCPP-NETLIB_BUILD_EXAMPLES=OFF '`
        + "-DCMAKE_BUILD_TYPE=$rel "`
        + '-DBOOST_ROOT=C:\ProgramData\chocolatey\lib\boost-msvc14\local '`
        + '-DBOOST_LIBRARYDIR=C:\ProgramData\chocolatey\lib\boost-msvc14\'`
        + 'local\lib64-msvc-14.0 '`
        + '-DOPENSSL_INCLUDE_DIR=C:\ProgramData\chocolatey\lib\openssl\'`
        + 'local\include '`
        + '-DOPENSSL_ROOT_DIR=C:\ProgramData\chocolatey\lib\openssl\local '`
        + "$source_dir"

  & 'cmake.exe' $params

  Set-Location $oldLocation
}

function Build-CppNetlibChocoPackage {
  param(
    [string] $build = '',
    [string] $version = '',
    [boolean] $rel = 'Release'
  )
  $packageName = 'cpp-netlib'
  $projectUrl = 'http://cpp-netlib.org/'
  $packageSourceUrl = 'https://github.com/cpp-netlib/cpp-netlib'
  Write-Host "[+] Building $packageName $version. . ." -foregroundcolor Green



  if (-not (Test-Path $build)) {
    Write-Host "[-] Did not find $build, creating." -foregroundcolor Yellow
    New-Item -ItemType Directory -Path $build
  }

  $code = New-Item -ItemType Directory -Path (Join-Path $build 'build')
  $target = New-Item -ItemType Directory -Path (Join-Path $build $packageName)
  $tools = New-Item -ItemType Directory -Path (Join-Path $target.name 'local\include')
  $tools = New-Item -ItemType Directory -Path (Join-Path $target.name 'local\lib')
  $nuspec = Get-Nuspec $packageName $version $projectUrl $packageSourceUrl 'local'
  $nuspec | Out-File -Encoding 'UTF8' (Join-Path $'.nuspec')

  Build-CppNetlib $code $version $rel


}

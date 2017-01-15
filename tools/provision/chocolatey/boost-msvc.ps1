#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function Build-BoostChocoPackage {
  param(
    [string] $build = '',
    [string] $version = ''
  )
  $packageName = 'boost-msvc14'
  $projectUrl = 'http://www.boost.org/'
  $packageSourceUrl = "https://sourceforge.net/projects/boost/files/boost/$version/"
  Write-Host "[+] Building $packageName $version. . ." -foregroundcolor Green

  $install = @"
`$version = $version
`$versionUnder = `$version.Split('.') -Join '_'
`$packageName = 'boost-msvc14'
`$ErrorActionPreference = 'Stop';
`$toolsDir = "`$(Split-Path -parent `$MyInvocation.MyCommand.Definition)"
`$url = "https://downloads.sourceforge.net/project/boost/boost-binaries/"`
  + "`$version/boost_`versionUnder-msvc-14.0-32.exe?r=https%3A%2F%2F"`
  + "sourceforge.net%2Fprojects%2Fboost%2Ffiles%2Fboost-binaries%2F`version%2F"
`$url64 = "https://downloads.sourceforge.net/project/boost/boost-binaries/"`
  + "`$version/boost_`versionUnder-msvc-14.0-64.exe?r=https%3A%2F%2F"`
  + "sourceforge.net%2Fprojects%2Fboost%2Ffiles%2Fboost-binaries%2F`version%2F"
`$packageRootDir = Resolve-Path ([System.IO.Path]::Combine(`$toolsDir, '..'))
`$extractPath = Join-Path `$packageRootDir 'local'
Remove-Item `$extractPath -Recurse -ErrorAction Ignore
mkdir `$extractPath > `$null

`$packageArgs = @{
  packageName   = `$packageName
  unzipLocation = `$toolsDir
  fileType      = 'EXE'
  url           = `$url
  url64bit      = `$url64
  silentArgs    = "/VERYSILENT /DIR=`"`$extractPath`""
  validExitCodes= @(0)
}

Install-ChocolateyPackage @packageArgs
"@

  $uninstall = @"
`$toolsDir = "`$(Split-Path -parent `$MyInvocation.MyCommand.Definition)"
`$ErrorActionPreference = 'Stop';
`$packageName = 'boost-msvc14'
`$softwareName = 'boost-msvc14*'
`$installerType = 'EXE'
`$extractPath = Join-Path `$packageRootDir 'local'
`$silentArgs = "/VERYSILENT /DIR=`"`$extractPath`""

`$packageArgs = @{
  packageName   = `$packageName
  unzipLocation = `$toolsDir
  fileType      = 'EXE'
  silentArgs    = "/VERYSILENT /DIR=`"`$extractPath`""
  validExitCodes= @(0)
}

Uninstall-ChocolateyPackage @packageArgs
"@

  if (-not (Test-Path $build)) {
    Write-Host "[-] Did not find $build, creating." -foregroundcolor Yellow
    New-Item -ItemType Directory -Path $build
  }
  $target = New-Item -ItemType Directory -Path (Join-Path $build 'boost-msvc14')
  $tools = New-Item -ItemType Directory -Path (Join-Path $target.name 'tools')
  $nuspec = Get-Nuspec $packageName $version $projectUrl $packageSourceUrl 'tools'

  $nuspec | Out-File -Encoding 'UTF8' (Join-Path $target.name "$packageName.nuspec")
  $install | Out-File -Encoding 'UTF8' (Join-Path $tools.name "chocolateyinstall.ps1")
  $uninstall | Out-File -Encoding 'UTF8' (Join-Path $tools.name "chocolateyuninstall.ps1")
}

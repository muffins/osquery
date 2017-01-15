#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

Write-Host '[+] Building osquery third party libraries for windows. . .'

if (-not (Test-Path (Join-Path (Get-location).Path `
    'tools\deployment\chocolatey\tools\osquery_utils.ps1'))) {
  Write-Host '[-] This script must be run from the repo root; exiting.'`
    -foregroundcolor Red
  exit
}
. (Join-Path (Get-location).Path `
   'tools\deployment\chocolatey\tools\osquery_utils.ps1')

if(-not (Get-Command choco -ErrorAction SilentlyContinue)) {
  Write-Host '[-] This build requires chocolatey which was not found in '`
    "the PATH. Run 'tools\make-win64-dev-env.bat' before continuing."` -foregroundcolor Yellow
  exit
}

function Main() {

  # Setup our environment for VS 2015 x64 building
  Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

  if(-not (Get-Command 7z -ErrorAction SilentlyContinue)) {
    Write-Host '[-] This build requires 7z which was not found in the PATH. '`
      'Installing via chocolatey.' -foregroundcolor Yellow
    choco install -y 7z -s https://chocolatey.org/api/v2/
  }

  # TODO: Add a check for the git.exe
}

$null = Main

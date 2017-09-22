#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

$osquery_utils = '.\tools\provision\osquery_utils.ps1'
$cwd = Get-Location
if (-not (Test-Path (Join-Path $cwd $osquery_utils))) {
  $msg = '[-] This script must be run from the osquery source root.'
  Write-Host $msg -ForegroundColor Red
  exit
}

if ((Get-Command vswhere) -eq '') {
  $msg = '[-] vswhere not found. Please re-run the provisioning script.'
  Write-Host $msg -ForegroundColor Red
  exit
}

. "$osquery_utils"

function Initialize-OsquerySolution () {
  $vswhere = (Get-Command vswhere).Source
  $vswhereArgs = @(
    '-latest'
  )
  Start-OsqueryProcess $vswhere $vswhereArgs
  


  Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

}

function New-OsqueryBuild() {

}

function main() {
  Initialize-OsquerySolution
  New-OsqueryBuild
}

$null = build

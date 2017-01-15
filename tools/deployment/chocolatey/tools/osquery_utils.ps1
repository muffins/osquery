#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Helper function to toggle the Deny-Write ACL placed on the
# osqueryd parent folder for 'safe' execution on Windows.
function Set-DenyWriteAcl {
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="Medium")]
  param(
    [string] $targetDir = '',
    [string] $action = ''
  )
  if (($action -ine 'Add') -and ($action -ine 'Remove')) {
    Write-Debug "[-] Invalid action in Set-DenyWriteAcl."
    return $false
  }
  if($PSCmdlet.ShouldProcess($targetDir)) {
    $acl = Get-Acl $targetDir
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $permType = [System.Security.AccessControl.AccessControlType]::Deny

    $permission = "everyone","write",$inheritanceFlag,$propagationFlag,$permType
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    # We only support adding or removing the ACL
    if ($action -ieq 'add') {
      $acl.SetAccessRule($accessRule)
    } else {
      $acl.RemoveAccessRule($accessRule)
    }
    $acl | Set-Acl $targetDir
    return $true
  }
  return $false
}

# This function ensures that the scripts are being run in the repo root, as
# we make assumptions about the locations of various scripts for sourcing.
function Test-ExecutionLocation {
  if (-not (Test-Path (Join-Path (Get-location).Path 'tools\make-win64-binaries.bat'))) {
    return $false
  }
  return $true
}

# Calls a `.bat` script file from within powershell.
function Invoke-BatchFile {
  param([string]$Path, [string]$Parameters)
  $tempFile = [IO.Path]::GetTempFileName()
  cmd.exe /c " `"$Path`" $Parameters && set > `"$tempFile`" "
  Get-Content $tempFile | Foreach-Object {
    if ($_ -match "^(.*?)=(.*)$") {
      Set-Content "env:\$($matches[1])" $matches[2]
    }
  }
  Remove-Item $tempFile
}

# Creates a new temporary directory
function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $dirname = [System.Guid]::NewGuid()
    $d = New-Item -ItemType Directory -Path (Join-Path $parent $dirname)
    return $parent+$d.name
}

# A helper function for generating the nuspec used by chocolatey.
function Get-ChocoNuspec {
  param(
    [string] $title = '',
    [string] $version = '',
    [string] $projectUrl = '',
    [string] $packageSourceUrl = '',
    [string] $filesDir = ''
  )
  return @"
<?xml version="1.0" encoding="utf-8"?>
<!-- Do not remove this test for UTF-8: if “Ω” doesn’t appear as greek uppercase omega letter enclosed in quotation marks, you should use an editor that supports UTF-8, not this one. -->
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>$title</id>
    <title>$title</title>
    <version>$version</version>
    <authors>$title</authors>
    <owners>$title</owners>
    <summary>osquery third party dependency</summary>
    <description>osquery third party dependency</description>
    <projectUrl>$projectUrl</projectUrl>
    <packageSourceUrl$packageSourceUrl</packageSourceUrl>
    <tags>$title</tags>
    <copyright></copyright>
    <licenseUrl>http://www.boost.org/users/license.html</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <releaseNotes></releaseNotes>
  </metadata>
  <files>
    <file src="$filesDir\**" target="$filesDir" />
  </files>
</package>
"@
}

# A helper function for generating a chocolatey install script for the osquery
# third party libraries.
function Get-ChocoInstall {

}

# A helper function for generating a chocolatey install script for the osquery
# third party libraries.
function Get-ChocoUninstall {

}

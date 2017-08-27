#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# Source the osquery utils script

# We make heavy use of Write-Host, because colors are awesome. #dealwithit.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", '', Scope="Function", Target="*")]
param()

function Main() {
  param(
    [string] $configPath = '',
    [string] $packsPath = '',
    [string] $certsPath = ''
  )

  $working_dir = Get-Location
  if ((-not (Get-Command candle.exe)) -or (-not (Get-Command light.exe))) {
    Write-Host '[-] WiX toolkig not found. ' +`
               'please run .\tools\make-win64-dev-env.bat before continuing!' `
               -ForegroundColor Red
    exit
  }

  if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host '[-] Powershell 5.0 or great is required for this script.' `
               -ForegroundColor Red
    exit
  }

  if (-not (Test-Path (Join-Path (Get-location).Path 'tools\make-win64-binaries.bat'))) {
    Write-Host '[-] This script must be run from the osquery repo root.' `
               -ForegroundColor Red
    exit
  }
  # Binaries might not be built, let's try to build them quick :)
  if (-not (Test-Path (Join-Path (Get-Location).Path 'build\windows10\osquery\Release\osqueryd.exe'))) {
    & '.\tools\make-win64-binaries.bat'
  }
  $shell = Join-Path $scriptPath 'build\windows10\osquery\Release\osqueryi.exe'
  $daemon = Join-Path $scriptPath 'build\windows10\osquery\Release\osqueryd.exe'
  if ((-not (Test-Path $shell)) -or (-not (Test-Path $daemon))) {
    Write-Host '[-] Unable to find osquery binaries, check build script output.' `
               -ForegroundColor Red
    exit
  }

  # Listing of artifacts bundled with osquery
  $scriptPath = Get-Location

  # bundle default certs
  if ($certsPath -eq '') {
    $chocoPath = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
    $certs = Join-Path "$chocoPath" 'lib\openssl\local\certs'
    if (-not (Test-Path $certs)) {
      Write-Debug '[*] Did not find openssl certs.pem, skipping.'
    }
  }

  # bundle default configuration
  if ($configPath -eq '') {
    $configPath = Join-Path $scriptPath 'tools\deployment\osquery.example.conf'
    if (-not (Test-Path $conf)) {
      Write-Debug '[*] Did not find example configuration, skipping.'
    }
  }

  # bundle default packs
  if ($packsPath -eq '') {
    $packsPath = Join-Path $scriptPath 'packs'
    if (-not (Test-Path $packs)) {
      Write-Debug '[*] Did not find example packs, skipping.'
    }
  }

  # Working directory and output of files will be in `build/msi`
  $buildPath = Join-Path $scriptPath 'build\msi'
  if (-not (Test-Path $buildPath)) {
    New-Item -Force -ItemType Directory -Path $buildPath
  }
  Set-Location $buildPath


  $wix =
@'
<?xml version='1.0' encoding='windows-1252'?>

<?define OsqueryVersion = '2.5.3'?>
<?define OsqueryUpgradeCode = 'ea6c7327-461e-4033-847c-acdf2b85dede'?>

<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi" xmlns:util="http://schemas.microsoft.com/wix/UtilExtension">
  <Product
    Name='osquery'
    Manufacturer='Facebook'
    Id='44363808-f75e-471b-95bb-bacb1c404c5e'
    UpgradeCode='$(var.OsqueryUpgradeCode)'
    Language='1033'
    Codepage='1252'
    Version='$(var.OsqueryVersion)'>

    <Package Id='*'
      Keywords='Installer'
      Description='osquery standalone installer'
      Comments='Facebooks opensource host intrusion detection agent'
      Manufacturer='Facebook'
      InstallerVersion='100'
      Languages='1033'
      Compressed='yes'
      SummaryCodepage='1252' />

    <MediaTemplate EmbedCab="yes" />

    <Upgrade Id='$(var.OsqueryUpgradeCode)'>
       <UpgradeVersion Minimum='$(var.OsqueryVersion)'
                       OnlyDetect='yes'
                       Property='NEWERVERSIONDETECTED'/>
    </Upgrade>

    <Condition Message='A newer version of osquery is already installed.'>
      NOT NEWERVERSIONDETECTED
    </Condition>

    <Condition Message="You need to be an administrator to install this product.">
        Privileged
    </Condition>

    <Property Id='SOURCEDIRECTORY' Value='packs'/>

    <Directory Id='TARGETDIR' Name='SourceDir'>
      <Directory Id='CommonAppDataFolder'>
        <Directory Id='INSTALLFOLDER' Name='osquery'>
          <Directory Id='DaemonFolder' Name='osqueryd'>
            <Component Id='osqueryd'
                Guid='41c9910d-bded-45dc-8f82-3cd00a24fa2f'>
              <CreateFolder>
                  <Permission User="NT AUTHORITY\SYSTEM" GenericAll="yes"/>
                  <Permission User="Administrators" GenericAll="yes"/>
                  <Permission User="Users" GenericRead="yes" GenericExecute="yes"/>
                  <Permission User="Everyone" GenericRead="yes" GenericExecute="yes"/>
              </CreateFolder>
              <File Id='osqueryd'
                Name='osqueryd.exe'
                Source='osqueryd.exe'
                KeyPath='yes'/>
              <ServiceInstall Id='osqueryd'
                Name='osqueryd'
                Account='NT AUTHORITY\SYSTEM'
                Arguments='--flagfile=C:\ProgramData\osquery\osquery.flags'
                Start='auto'
                Type='ownProcess'
                Vital='yes'
                ErrorControl='critical'/>
              <ServiceControl Id='osqueryd'
                Name='osqueryd'
                Stop='both'
                Start='install'
                Remove='uninstall'
                Wait='no'/>
            </Component>
          </Directory>
          <Directory Id='LogFolder' Name='log'/>
          <Component Id='osqueryi' Guid='6a49524e-52b0-4e99-876f-ec50c0082a04'>
            <File Id='osqueryi'
              Name='osqueryi.exe'
              Source='osqueryi.exe'
              KeyPath='yes'/>
          </Component>
          <Component Id='extras' Guid='3f435561-8fe7-4725-975a-95930c44d063'>
            <File Id='osquery.conf'
              Name='osquery.conf'
              Source='osquery.conf'
              KeyPath='yes'/>
            <File Id='osquery.flags'
              Name='osquery.flags'
              Source='osquery.flags'/>
            <File Id='osquery_utils.ps1'
              Name='osquery_utils.ps1'
              Source='osquery_utils.ps1'/>
            <File Id='postinstall'
              Name='post-install.bat'
              Source='post-install.bat'/>
            <CopyFile Id='packs'
              SourceProperty='packs'
              DestinationDirectory='INSTALLFOLDER'/>
          </Component>
          <Directory Id="FileSystemLogging" Name="log"/>
        </Directory>
      </Directory>
    </Directory>

    <Component Id='CreateFileSystemLogging'
               Directory='FileSystemLogging'
               Guid='bda18e0c-d356-441d-a264-d3e2c1718979'>
      <CreateFolder/>
    </Component>

    <Feature Id='Complete' Level='1'>
      <ComponentRef Id='osqueryd'/>
      <ComponentRef Id='osqueryi'/>
      <ComponentRef Id='extras'/>
      <ComponentRef Id='CreateFileSystemLogging'/>
    </Feature>

    <CustomAction Id="PostInstallScript"
                  ExeCommand="[INSTALLFOLDER]post-install.bat"
                  Directory="INSTALLFOLDER"
                  Execute="commit"
                  Return="asyncNoWait"/>

    <CustomAction Id="PreUninstallScript"
                  ExeCommand="cmd.exe /c &quot;[INSTALLFOLDER]pre-uninstall.bat&quot;"
                  Directory="INSTALLFOLDER"
                  Execute="commit"
                  Return="asyncNoWait"/>

    <InstallExecuteSequence>
      <Custom Action="PostInstallScript" After="InstallFiles" >NOT Installed</Custom>
    </InstallExecuteSequence>

  </Product>
</Wix>
'@

  $wix | Out-File -Encoding 'UTF8' "$buildPath\osquery.wxs"


  Write-Host "[+] MSI Package written to $osqueryBuildPath" -ForegroundColor Green
  Set-Location $workingDir
}

$null = Main

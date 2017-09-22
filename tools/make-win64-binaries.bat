::  Copyright (c) 2014-present, Facebook, Inc.
::  All rights reserved.
::
::  This source code is licensed under the BSD-style license found in the
::  LICENSE file in the root directory of this source tree. An additional grant
::  of patent rights can be found in the PATENTS file in the same directory.

@echo off
:: call "%VS140COMNTOOLS%vcvarsqueryregistry.bat" 64bit
call "%VCINSTALLDIR%vcvarsall.bat" amd64

:: Suppress the error message generated if the directory already exists
md .\build\windows10 2>NUL
cd .\build\windows10

:: Generate the osquery solution
cmake ..\.. -G "Visual Studio 14 2015 Win64"

IF DEFINED RELWITHDEB (
  SET rel="RelWithDebInfo"
) ELSE (
  SET rel="Release"
)

for %%t in (shell,daemon) do (
  cmake --build . --target %%t --config %rel% -- /verbosity:minimal /maxcpucount
  if errorlevel 1 goto end
)

:: Build and run the tests for osquery if SKIP_TESTS isn't defined
if defined SKIP_TESTS goto end
for %%t in (osquery_tests,osquery_additional_tests,osquery_tables_tests) do (
  cmake --build . --target %%t --config %rel% -- /verbosity:minimal /maxcpucount
  if errorlevel 1 goto end
)
ctest -C %rel% --output-on-failure
:end

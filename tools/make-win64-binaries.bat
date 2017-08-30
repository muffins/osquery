@echo off

:: Suppress the error message generated if the directory already exists
md .\build\windows10 2>NUL
cd .\build\windows10

:: Generate the osquery solution
IF NOT DEFINED OSQ32 (
  SET generator="Visual Studio 14 2015 Win64"
  call "%VS140COMNTOOLS%vcvarsqueryregistry.bat" 64bit
  call "%VCINSTALLDIR%vcvarsall.bat" amd64
) ELSE (
  SET generator="Visual Studio 14 2015"
  call "%VS140COMNTOOLS%vcvarsqueryregistry.bat" 32bit
  call "%VCINSTALLDIR%vcvarsall.bat" x86
)

:: Build the osquery solution
cmake ..\..\ -G %generator%

IF DEFINED DEBUG (
  SET rel="RelWithDebInfo"
) ELSE (
  SET rel="Release"
)

:: Build the daemon binary and copy it to the shell
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

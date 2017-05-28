call "%VS140COMNTOOLS%vcvarsqueryregistry.bat" 64bit
call "%VCINSTALLDIR%vcvarsall.bat" amd64

mkdir .\build\windows10
cd .\build\windows10
cmake ..\.. -G "Visual Studio 14 2015 Win64"

for %%t in (shell, external_extension_awesome) do (
  cmake --build . --target %%t --config Release -- /verbosity:minimal /maxcpucount
  if errorlevel 1 goto end
)


:end

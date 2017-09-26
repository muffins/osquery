

# Build Process:
```
C:\Users\thor\work\repos\osquery [master ≡]
λ  cat .\external\extension_test\sample_extension.cpp
// Note 1: Include the sdk.h helper.
#include <osquery/sdk.h>

using namespace osquery;

// Note 2: Define at least one plugin.
class ExampleTablePlugin : public tables::TablePlugin {
 private:
  tables::TableColumns columns() const override {
    return {
      std::make_tuple("example_text", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("example_integer", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

  QueryData generate(tables::QueryContext& request) override {
    QueryData results;
    Row r;

    r["example_text"] = "example";
    r["example_integer"] = INTEGER(1);
    results.push_back(r);
    return results;
  }
};

// Note 3: Use REGISTER_EXTERNAL to define your plugin.
REGISTER_EXTERNAL(ExampleTablePlugin, "table", "example");

int main(int argc, char* argv[]) {
  // Note 4: Start logging, threads, etc.
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  // Note 5: Connect to osqueryi or osqueryd.
  auto status = startExtension("example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally shutdown.
  runner.waitForShutdown();
  return 0;
}

C:\Users\thor\work\repos\osquery [master ≡]
λ  .\tools\make-win64-binaries.bat
--
-- Welcome to osquery's build-- thank you for your patience! :)
-- For a brief tutorial see: http://osquery.readthedocs.io/en/stable/development/building/
-- Building for platform Windows (windows, windows10)
-- Building osquery version  2.8.0-14-g9d332617 sdk 2.8.0
mkdir: cannot create directory 'C:/Users/thor/work/repos/osquery/build/windows10/generated': File exists
-- Configuring done
-- Generating done
-- Build files have been written to: C:/Users/thor/work/repos/osquery/build/windows10
Microsoft (R) Build Engine version 14.0.25420.1
Copyright (C) Microsoft Corporation. All rights reserved.
...

  osquery_sqlite.vcxproj -> C:\Users\thor\work\repos\osquery\build\windows10\third-party\sqlite3\osquery_sqlite.dir\Release\osquery_sqlite.lib
  osquery_extensions.vcxproj -> C:\Users\thor\work\repos\osquery\build\windows10\osquery\extensions\osquery_extensions.dir\Release\osquery_extensions.lib
...

  osquery_extensions.vcxproj -> C:\Users\thor\work\repos\osquery\build\windows10\osquery\extensions\osquery_extensions.dir\Release\osquery_extensions.lib
...
  osquery_tables_tests.vcxproj -> C:\Users\thor\work\repos\osquery\build\windows10\osquery\Release\osquery_tables_tests.exe
Test project C:/Users/thor/work/repos/osquery/build/windows10
    Start 1: osquery_tests
1/5 Test #1: osquery_tests ....................   Passed    1.92 sec
    Start 2: osquery_additional_tests
2/5 Test #2: osquery_additional_tests .........   Passed   38.74 sec
    Start 3: osquery_tables_tests
3/5 Test #3: osquery_tables_tests .............   Passed    1.94 sec
    Start 4: python_test_osqueryi
4/5 Test #4: python_test_osqueryi .............   Passed   67.82 sec
    Start 5: python_test_osqueryd
5/5 Test #5: python_test_osqueryd .............   Passed   19.57 sec

100% tests passed, 0 tests failed out of 5

Total Test time (real) = 130.09 sec
C:\Users\thor\work\repos\osquery [master ≡]
λ  cd .\build\windows10\

C:\Users\thor\work\repos\osquery\build\windows10 [master ≡]
λ  (Get-Command Invoke-BatchFile).Definition

  param([string]$Path, [string]$Parameters)
  $tempFile = [IO.Path]::GetTempFileName()
  cmd.exe /c " `"$Path`" $Parameters && set > `"$tempFile`" "
  Get-Content $tempFile | Foreach-Object {
    if ($_ -match "^(.*?)=(.*)$") {
      Set-Content "env:\$($matches[1])" $matches[2]
        }
  }
  Remove-Item $tempFile

C:\Users\thor\work\repos\osquery\build\windows10 [master ≡]
λ  Invoke-BatchFile "$env:VS140COMNTOOLS\..\..\vc\vcvarsall.bat" amd64

C:\Users\thor\work\repos\osquery\build\windows10 [master ≡]
λ   msbuild osquery.sln /p:Configuration=Release /p:PlatformType=x64 /p:Platform=x64 /t:external_extension_test /m /v:m

Microsoft (R) Build Engine version 14.0.25420.1
Copyright (C) Microsoft Corporation. All rights reserved.

...

  sample_extension.cpp
  LINK : /LTCG specified but no code generation required; remove /LTCG from the link command line to improve linker performance
  external_extension_test.vcxproj -> C:\Users\thor\work\repos\osquery\build\windows10\external\Release\external_extension_test.ext.exe

```

# Deployment Process:
```
C:\Users\thor\work\repos\osquery [master ≡]
λ  cp .\build\windows10\external\Release\external_extension_test.ext.exe C:\ProgramData\osquery\extensions\example.exe

C:\Users\thor\work\repos\osquery [master ≡]
λ  cat C:\ProgramData\osquery\osquery.flags
--disable_extensions=false
--config_path=C:\ProgramData\osquery\osquery.conf
--config_plugin=filesystem
--logger_plugin=filesystem
--logger_path=C:\ProgramData\osquery\log
--extensions_autoload=C:\ProgramData\osquery\extensions.load

C:\Users\thor\work\repos\osquery [master ≡]
λ  . .\tools\provision\chocolatey\osquery_utils.ps1
C:\Users\thor\work\repos\osquery [master ≡]

λ  Set-DenyWriteAcl C:\ProgramData\osquery\extensions 'Add'
True

C:\Users\thor\work\repos\osquery [master ≡]
λ  osqueryi --flagfile=C:\ProgramData\osquery\osquery.flags
Using a virtual database. Need help, type '.help'
osquery> .tables
...
  => etc_services
  => example
  => file
  => hash
...
osquery> select * from example;
+--------------+-----------------+
| example_text | example_integer |
+--------------+-----------------+
| example      | 1               |
+--------------+-----------------+
osquery> .quit

C:\Users\thor\work\repos\osquery [master ≡]
λ  cat C:\ProgramData\osquery\osquery.conf
{
  "options": { },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    },
    "extension_sample": {
      "query": "SELECT * FROM example;",
      "interval": 5,
      "snapshot": "true"
    }
  }
}

C:\Users\thor\work\repos\osquery [master ≡]
λ  Start-Service osqueryd

C:\Users\thor\work\repos\osquery [master ≡]
λ  Get-Service osqueryd

Status   Name               DisplayName
------   ----               -----------
Running  osqueryd           osqueryd

C:\Users\thor\work\repos\osquery [master ≡]
λ  tail -f C:\ProgramData\osquery\log\osqueryd.snapshots.log
{"snapshot":[{"example_integer":"1","example_text":"example"}],"action":"snapshot","name":"extension_sample","hostIdentifier":"TESTFAC-MMFN45S","calendarTime":"Tue Sep 26 19:32:30 2017 UTC","unixTime":"1506454350","epoch":"0"}
{"snapshot":[{"example_integer":"1","example_text":"example"}],"action":"snapshot","name":"extension_sample","hostIdentifier":"TESTFAC-MMFN45S","calendarTime":"Tue Sep 26 19:32:35 2017 UTC","unixTime":"1506454355","epoch":"0"}
{"snapshot":[{"example_integer":"1","example_text":"example"}],"action":"snapshot","name":"extension_sample","hostIdentifier":"TESTFAC-MMFN45S","calendarTime":"Tue Sep 26 19:32:41 2017 UTC","unixTime":"1506454361","epoch":"0"}
{"snapshot":[{"example_integer":"1","example_text":"example"}],"action":"snapshot","name":"extension_sample","hostIdentifier":"TESTFAC-MMFN45S","calendarTime":"Tue Sep 26 19:32:46 2017 UTC","unixTime":"1506454366","epoch":"0"}
...

C:\Users\thor\Desktop\tmp
λ  l C:\ProgramData\osquery\log\


    Directory: C:\ProgramData\osquery\log


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/26/2017  12:32 PM            490 osqueryd.INFO.20170926-123230.10976
-a----        9/26/2017  12:17 PM              0 osqueryd.results.log
-a----        9/26/2017  12:33 PM           3632 osqueryd.snapshots.log
```

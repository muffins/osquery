/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Winsvc.h>
#include <psapi.h>

#include <iostream>
#include <string>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/windows/registry.h"

#pragma comment(lib, "Advapi32.lib")

namespace osquery {
namespace tables {

const std::string kDrvStartType[] = {
    "BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED"};

const std::string kDrvStatus[] = {"UNKNOWN",
                                  "STOPPED",
                                  "START_PENDING",
                                  "STOP_PENDING",
                                  "RUNNING",
                                  "CONTINUE_PENDING",
                                  "PAUSE_PENDING",
                                  "PAUSED"};

const std::map<int, std::string> kDriverType = {
    {0x00000001, "KERNEL"}, {0x00000002, "FILE_SYSTEM"},
};

static std::map<std::string, std::string> LoadedDrivers;

// Nit: Do you mind doing caml casing for the function? `queryDrvInfo` instead?
bool QueryDrvInfo(const SC_HANDLE& schScManager,
                  ENUM_SERVICE_STATUS_PROCESS& svc,
                  Row& r) {
  DWORD cbBufSize = 0;

  auto schService =
      OpenService(schScManager, svc.lpServiceName, SERVICE_QUERY_CONFIG);

  if (schService == nullptr) {
    TLOG << "OpenService failed (" << GetLastError() << ")";
    return FALSE;
  }

  QueryServiceConfig(schService, nullptr, 0, &cbBufSize);
  auto lpsc = (LPQUERY_SERVICE_CONFIG)malloc(cbBufSize);
  if (!QueryServiceConfig(schService, lpsc, cbBufSize, &cbBufSize)) {
    TLOG << "QueryServiceConfig failed (" << GetLastError() << ")";
  }

  QueryServiceConfig2(
      schService, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &cbBufSize);
  auto lpsd = (LPSERVICE_DESCRIPTION)malloc(cbBufSize);
  if (!QueryServiceConfig2(schService,
                           SERVICE_CONFIG_DESCRIPTION,
                           (LPBYTE)lpsd,
                           cbBufSize,
                           &cbBufSize)) {
    TLOG << "QueryServiceConfig2 failed (" << GetLastError() << ")";
  }

  // SCM can provide more info about the driver but not all drivers are
  // managed by SCM, So Here we remove driver from LoadedDrivers list to avoid
  // duplicates
  // As the driver is already in SCM list.
  LoadedDrivers.erase(lpsc->lpBinaryPathName);

  r["name"] = SQL_TEXT(svc.lpServiceName);
  r["display_name"] = SQL_TEXT(svc.lpDisplayName);
  r["status"] = SQL_TEXT(kDrvStatus[svc.ServiceStatusProcess.dwCurrentState]);
  r["start_type"] = SQL_TEXT(kDrvStartType[lpsc->dwStartType]);
  r["path"] = SQL_TEXT(lpsc->lpBinaryPathName);

  if (kDriverType.count(lpsc->dwServiceType) > 0) {
    r["driver_type"] = SQL_TEXT(kDriverType.at(lpsc->dwServiceType));
  } else {
    r["driver_type"] = SQL_TEXT("UNKNOWN");
  }

  QueryData regResults;
  queryKey("HKEY_LOCAL_MACHINE",
           "SYSTEM\\CurrentControlSet\\Services\\" + r["name"],
           regResults);
  for (const auto& aKey : regResults) {
    if (aKey.at("name") == "Owners") {
      r["inf"] = SQL_TEXT(aKey.at("data"));
    }
  }

  free(lpsc);
  free(lpsd);
  CloseServiceHandle(schService);
  return TRUE;
}

void EnumLoadedDrivers() {
  DWORD bytesNeeded = 0;
  int driversCount = 0;

  auto ret = EnumDeviceDrivers(nullptr, 0, &bytesNeeded);
  auto drvBaseAddr = (LPVOID*)malloc(bytesNeeded);

  ret = EnumDeviceDrivers(drvBaseAddr, bytesNeeded, &bytesNeeded);

  driversCount = bytesNeeded / sizeof(LPVOID);

  if (ret && (bytesNeeded > 0)) {
    auto szDriverPath = (LPSTR)malloc(MAX_PATH);
    auto szDriverName = (LPSTR)malloc(MAX_PATH);

    for (int i = 0; i < driversCount; i++) {
      if (GetDeviceDriverFileName(drvBaseAddr[i], szDriverPath, MAX_PATH)) {
        GetDeviceDriverBaseName(drvBaseAddr[i], szDriverName, MAX_PATH);
        LoadedDrivers[szDriverPath] = szDriverName;
      }
    }
  } else {
    TLOG << "EnumDeviceDrivers failed; array size needed is" << bytesNeeded;
  }
}

QueryData genDrivers(QueryContext& context) {
  DWORD bytesNeeded = 0;
  DWORD serviceCount = 0;
  QueryData results;

  // Get All Loaded Drivers including ones managed by SCM
  EnumLoadedDrivers();

  auto schScManager = OpenSCManager(nullptr, nullptr, GENERIC_READ);
  if (schScManager == nullptr) {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
    return {};
  }

  EnumServicesStatusEx(schScManager,
                       SC_ENUM_PROCESS_INFO,
                       SERVICE_DRIVER,
                       SERVICE_STATE_ALL,
                       nullptr,
                       0,
                       &bytesNeeded,
                       &serviceCount,
                       nullptr,
                       nullptr);

  auto buf = malloc(bytesNeeded);
  if (EnumServicesStatusEx(schScManager,
                           SC_ENUM_PROCESS_INFO,
                           SERVICE_DRIVER,
                           SERVICE_STATE_ALL,
                           (LPBYTE)buf,
                           bytesNeeded,
                           &bytesNeeded,
                           &serviceCount,
                           nullptr,
                           nullptr)) {
    ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)buf;
    for (DWORD i = 0; i < serviceCount; ++i) {
      Row r;
      if (QueryDrvInfo(schScManager, services[i], r)) {
        results.push_back(r);
      }
    }
  } else {
    TLOG << "EnumServiceStatusEx failed (" << GetLastError() << ")";
  }

  free(buf);
  CloseServiceHandle(schScManager);

  for (const auto& element : LoadedDrivers) {
    Row r;
    r["name"] = "<" + element.second + ">";
    r["path"] = element.first;
    r["status"] = SQL_TEXT(kDrvStatus[4]);
    results.push_back(r);
  }

  return results;
}
}
}

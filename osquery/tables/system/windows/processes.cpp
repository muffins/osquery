/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/system.h>
#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {
int getUidFromSid(PSID sid);
int getGidFromSid(PSID sid);
namespace tables {

void setSeDbgPrivs(bool enable) {
  HANDLE procTok;
  OpenProcessToken(
      GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &procTok);

  TOKEN_PRIVILEGES tp;
  LUID luid;
  LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid);

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

  AdjustTokenPrivileges(
      procTok, false, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
}

void win32GenProcess(PROCESSENTRY32 procEntry, Row& r) {
  auto pid = procEntry.th32ProcessID;
  auto currentPid = GetCurrentProcessId();

  r["pid"] = INTEGER(pid);
  r["parent"] = INTEGER(procEntry.th32ParentProcessID);
  r["nice"] = INTEGER(procEntry.pcPriClassBase);
  r["name"] = procEntry.szExeFile;

  std::vector<char> fileName(MAX_PATH + 1, 0x0);
  unsigned long fileNameSize = MAX_PATH;

  // setSeDbgPrivs(true);
  /// If we can, open with QUERY_INFO and VM_READ, otherwise it's
  /// likely the process is protected, so we open with QUERY_LIMITED_INFO
  auto hProcess =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
  if (hProcess == nullptr) {
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
  }

  long uid = -1;
  long gid = -1;
  if (GetLastError() == ERROR_ACCESS_DENIED) {
    uid = 0;
    gid = 0;
  }

  QueryFullProcessImageName(hProcess, 0, fileName.data(), &fileNameSize);
  r["path"] = SQL_TEXT(fileName.data());
  r["on_disk"] = osquery::pathExists(r["path"]).toString();

  FILETIME creationTime;
  FILETIME exitTime;
  FILETIME kernelTime;
  FILETIME userTime;
  auto ret = GetProcessTimes(
      hProcess, &creationTime, &exitTime, &kernelTime, &userTime);
  if (ret != 0) {
    FILETIME ftCurrentTime;
    SYSTEMTIME stCurrentTime;
    GetSystemTime(&stCurrentTime);
    SystemTimeToFileTime(&stCurrentTime, &ftCurrentTime);
    auto startTime = filetimeToUnixtime(creationTime) -
                (filetimeToUnixtime(ftCurrentTime) - (GetTickCount64() / 1000));
    /// Kernel and User time values are ticks since proc start, as opposed to
    /// ticks since Epoch

    auto quadUserTime =
      ((static_cast<unsigned long long>(userTime.dwHighDateTime) << 32) |
        userTime.dwLowDateTime);
    auto quadSysTime =
      ((static_cast<unsigned long long>(kernelTime.dwHighDateTime) << 32) |
        kernelTime.dwLowDateTime);

    r["start_time"] = BIGINT(startTime);
    r["user_time"] = BIGINT(quadUserTime / 10000000);
    r["system_time"] = BIGINT(quadSysTime / 10000000);
  } else {
    r["start_time"] = BIGINT(-1);
    r["user_time"] = BIGINT(-1);
    r["system_time"] = BIGINT(-1);
  }

  PROCESS_MEMORY_COUNTERS_EX memCnt;
  ret = GetProcessMemoryInfo(hProcess,
                             (PROCESS_MEMORY_COUNTERS*)&memCnt,
                             sizeof(PROCESS_MEMORY_COUNTERS_EX));
  if (ret == 0) {
    r["wired_size"] = BIGINT(-1);
    r["resident_size"] = BIGINT(-1);
    r["total_size"] = BIGINT(-1);
  } else {
    r["wired_size"] = BIGINT(memCnt.QuotaNonPagedPoolUsage);
    r["resident_size"] = BIGINT(memCnt.PrivateUsage);
    r["total_size"] = BIGINT(memCnt.WorkingSetSize);
  }

  // TODO:
  r["state"] = "-1";
  r["cmdline"] = "-1";
  r["root"] = "-1";
  r["cwd"] = "-1";
  r["pgroup"] = "-1";
  r["euid"] = "-1";
  r["suid"] = "-1";
  r["egid"] = "-1";
  r["sgid"] = "-1";

  /// Get the process UID and GID from it's SID
  HANDLE tok = nullptr;
  unsigned long tokOwnerBuffLen;
  std::vector<char> tokOwner(sizeof(TOKEN_OWNER), 0x0);
  OpenProcessToken(hProcess, TOKEN_READ, &tok);
  if (tok != nullptr) {
    ret = GetTokenInformation(tok, TokenOwner, nullptr, 0, &tokOwnerBuffLen);
    if (ret == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      tokOwner.resize(tokOwnerBuffLen);
      ret = GetTokenInformation(
          tok, TokenOwner, tokOwner.data(), tokOwnerBuffLen, &tokOwnerBuffLen);
    }
  }
  if (uid != 0 && ret != 0 && !tokOwner.empty()) {
    auto sid = PTOKEN_OWNER(tokOwner.data())->Owner;
    r["uid"] = INTEGER(getUidFromSid(sid));
    r["gid"] = INTEGER(getGidFromSid(sid));
  } else {
    r["uid"] = INTEGER(uid);
    r["gid"] = INTEGER(gid);
  }

  if (hProcess != nullptr) {
    CloseHandle(hProcess);
    hProcess = nullptr;
  }
  if (tok != nullptr) {
    CloseHandle(tok);
    tok = nullptr;
  }
  results_data.push_back(r);
}

QueryData genProcesses(QueryContext& context) {
  QueryData results;

  /// Win32 APIs
  HANDLE hProcessSnap;
  PROCESSENTRY32 pe32;

  // Take a snapshot of all processes in the system.
  hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE) {
    LOG(INFO) << "Failed to obtain Process Snapshot, Error Code: ("
              << GetLastError() << ")";
    return results;
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof(PROCESSENTRY32);

  // Retrieve information about the first process, and exit if unsuccessful
  if (!Process32First(hProcessSnap, &pe32)) {
    LOG(INFO) << "Failed to obtain Process Snapshot, Error Code: ("
              << GetLastError() << ")";
    CloseHandle(hProcessSnap);
    return results;
  }

  // Now walk the snapshot of processes, and display information about each
  // process in turn
  do {
    Row r;
    win32GenProcess(pe32, r);
    results.push_back(r);
  } while (Process32Next(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);
  return results;
}
}
}

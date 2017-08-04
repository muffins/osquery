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
#include <string>

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

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include <osquery/filesystem/fileops.h>

namespace osquery {
int getUidFromSid(PSID sid);
int getGidFromSid(PSID sid);
namespace tables {

/// Enumerate the details for all processes running on a system
Status enumerateProcesses(QueryData& results) {
  
  auto procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(procSnap == INVALID_HANDLE_VALUE) {
    return Status(1, "Failed to open process snapshot");
  }

  PROCESSENTRY32 procEntry;
  procEntry.dwSize = sizeof(PROCESSENTRY32);

  auto ret = Process32First(procSnap, &procEntry);

  if(ret == FALSE) {
    CloseHandle(procSnap);
    return Status(1, "Failed to open first process");
  }

  while(ret != FALSE) {
    Row r;
    r["pid"] = BIGINT(procEntry.th32ProcessID);
    r["name"] = SQL_TEXT(procEntry.szExeFile);
    r["parent"] = BIGINT(procEntry.th32ParentProcessID);
    r["nice"] = INTEGER(procEntry.pcPriClassBase);
    r["threads"] = INTEGER(procEntry.cntThreads);
    
    // TODO:
    r["cwd"] = "";
    r["state"] = "";
    r["root"] = "";
    r["pgroup"] = BIGINT(-1);

    auto proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procEntry.th32ProcessID);
    
    // The process is privileged, and we cannot open it for reading
    if(proc == nullptr) {
      r["uid"] = BIGINT(-1);
      r["gid"] = BIGINT(-1);
      r["euid"] = BIGINT(-1);
      r["egid"] = BIGINT(-1);
      r["suid"] = BIGINT(-1);
      r["sgid"] = BIGINT(-1);
      r["on_disk"] = INTEGER(-1);
      r["user_time"] = BIGINT(-1);
      r["system_time"] = BIGINT(-1);
      r["start_time"] = BIGINT(-1);
      r["wired_size"] = BIGINT(-1);
      r["resident_size"] = BIGINT(-1);
      r["total_size"] = BIGINT(-1);
      results.push_back(r);
      ret = Process32Next(procSnap, &procEntry);
      continue;
    }

    std::vector<char> exeName(MAX_PATH, 0);
    unsigned long exeNameLen = MAX_PATH;
    auto procRet = QueryFullProcessImageName(proc, 0, exeName.data(), &exeNameLen);
    if(procRet == FALSE) {
      VLOG(1) << "Failed to get Full process image name with " << GetLastError();
      r["path"] = "";
    } else {
      r["path"] = exeName.data();
    }
    r["on_disk"] = INTEGER(osquery::pathExists(r["path"]).getCode());

    PROCESS_MEMORY_COUNTERS_EX pmc;
    procRet = GetProcessMemoryInfo(proc, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc));
    if(procRet == FALSE) {
      r["wired_size"] = BIGINT(-1);
      r["resident_size"] = BIGINT(-1);
    } else {
      r["wired_size"] = BIGINT(pmc.PrivateUsage);
      r["resident_size"] = BIGINT(pmc.WorkingSetSize);
    }

    FILETIME createTime;
    FILETIME exitTime;
    FILETIME kernelTime;
    FILETIME userTime;
    procRet = GetProcessTimes(proc, &createTime, &exitTime, &kernelTime, &userTime);
    if(procRet == FALSE) {
      r["user_time"] = BIGINT(-1);
      r["system_time"] = BIGINT(-1);
      r["start_time"] = BIGINT(-1);
    } else {
      // Windows stores proc times in 100 nanosecond ticks
      ULARGE_INTEGER utime;
      utime.HighPart = userTime.dwHighDateTime;
      utime.LowPart = userTime.dwLowDateTime;
      r["user_time"] = BIGINT(utime.QuadPart / 10000000);
      utime.HighPart = kernelTime.dwHighDateTime;
      utime.LowPart = kernelTime.dwLowDateTime;
      r["system_time"] = BIGINT(utime.QuadPart / 10000000);
      r["start_time"] = BIGINT(osquery::filetimeToUnixtime(createTime));
    }

    HANDLE tok;
    auto userProcessed = false;
    procRet = OpenProcessToken(proc, TOKEN_READ, &tok);
    if(procRet != FALSE) {
      std::vector<char> tokBuff;
      unsigned long tokBuffSize = 0;
      procRet = GetTokenInformation(tok, TokenUser, nullptr, 0, &tokBuffSize);
      if(procRet != FALSE || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        tokBuff.resize(tokBuffSize, 0);
        procRet = GetTokenInformation(tok, TokenUser, tokBuff.data(), tokBuffSize, &tokBuffSize);
        auto tokUser = PTOKEN_USER(tokBuff.data());
        r["uid"] = BIGINT(osquery::getUidFromSid(tokUser->User.Sid));
        r["gid"] = BIGINT(osquery::getGidFromSid(tokUser->User.Sid));

        // TODO: Parse out any privileges the token might have
        r["euid"] = BIGINT(-1);
        r["egid"] = BIGINT(-1);
        r["suid"] = BIGINT(-1);
        r["sgid"] = BIGINT(-1);
        userProcessed = true;
      } else {
        VLOG(1) << "GetTokenInformation failed with (" << GetLastError() << ")";
      }
    } 

    // Failing to opent he process token likely means we do not have access
    if (!userProcessed) {
      r["uid"] = BIGINT(-1);
      r["gid"] = BIGINT(-1);
      r["euid"] = BIGINT(-1);
      r["egid"] = BIGINT(-1);
      r["suid"] = BIGINT(-1);
      r["sgid"] = BIGINT(-1);
    }
    CloseHandle(tok);

    // Grab whatever values we weren't able to query from WMI
    auto query = "select CommandLine, VirtualSize from Win32_Process where Handle = " + r["pid"];
    WmiRequest request(query);
    if (request.getStatus().ok()) {
      for(const auto& item : request.results()) {
        item.GetString("CommandLine", r["cmd_line"]);
        unsigned long virtSize = 0;
        item.GetUnsignedLong("VirtualSize", virtSize);
        r["total_size"] = BIGINT(virtSize);
      }
    } else {
      r["cmd_line"] = "";
      r["total_size"] = BIGINT(-1);
    }

    results.push_back(r);
    CloseHandle(proc);
    ret = Process32Next(procSnap, &procEntry);
  }
  CloseHandle(procSnap);
  return Status();
}

QueryData genProcesses(QueryContext& context) {
  QueryData results;

  /*
  std::string query = "SELECT * FROM Win32_Process";
  std::set<unsigned long> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
      if (pid > 0) {
        pidlist.insert(pid);
      }
    }
    // None of the constraints returned valid pids, bail out early
    if (pidlist.size() == 0) {
      return results;
    }
  }
  */
  auto s = enumerateProcesses(results);
  if(!s.ok()) {
    VLOG(1) << s.getMessage();
  }

  return results;
}
} // namespace tables
} // namespace osquery

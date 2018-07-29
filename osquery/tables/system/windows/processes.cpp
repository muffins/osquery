/**
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under both the Apache 2.0 license (found in the
*  LICENSE file in the root directory of this source tree) and the GPLv2 (found
*  in the COPYING file in the root directory of this source tree).
*  You may select, at your option, one of the above-listed licenses.
*/

#include <map>
#include <string>

#define _WIN32_DCOM

#include <Windows.h>
#include <iomanip>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {
  int getUidFromSid(PSID sid);
  int getGidFromSid(PSID sid);
  namespace tables {

    const std::map<unsigned long, std::string> kMemoryConstants = {
      { PAGE_EXECUTE, "PAGE_EXECUTE" },
      { PAGE_EXECUTE_READ, "PAGE_EXECUTE_READ" },
      { PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE" },
      { PAGE_EXECUTE_WRITECOPY, "PAGE_EXECUTE_WRITECOPY" },
      { PAGE_NOACCESS, "PAGE_NOACCESS" },
      { PAGE_READONLY, "PAGE_READONLY" },
      { PAGE_READWRITE, "PAGE_READWRITE" },
      { PAGE_WRITECOPY, "PAGE_WRITECOPY" },
      { PAGE_GUARD, "PAGE_GUARD" },
      { PAGE_NOCACHE, "PAGE_NOCACHE" },
      { PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE" },
    };

    /// Given a pid, enumerates all loaded modules and memory pages for that process
    Status genMemoryMap(unsigned long pid, QueryData& results) {
      auto proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
      if (proc == nullptr) {
        Row r;
        r["pid"] = INTEGER(pid);
        r["start"] = INTEGER(-1);
        r["end"] = INTEGER(-1);
        r["permissions"] = "";
        r["offset"] = INTEGER(-1);
        r["device"] = "-1";
        r["inode"] = INTEGER(-1);
        r["path"] = "";
        r["pseudo"] = INTEGER(-1);
        results.push_back(r);
        return Status(1, "Failed to open handle to process " + std::to_string(pid));
      }
      auto modSnap =
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
      if (modSnap == INVALID_HANDLE_VALUE) {
        CloseHandle(proc);
        return Status(1, "Failed to enumerate modules for " + std::to_string(pid));
      }

      auto formatMemPerms = [](unsigned long perm) {
        std::vector<std::string> perms;
        for (const auto& kv : kMemoryConstants) {
          if (kv.first & perm) {
            perms.push_back(kv.second);
          }
        }
        return osquery::join(perms, " | ");
      };

      MODULEENTRY32 me;
      MEMORY_BASIC_INFORMATION mInfo;
      me.dwSize = sizeof(MODULEENTRY32);
      auto ret = Module32First(modSnap, &me);
      while (ret != FALSE) {
        for (auto p = me.modBaseAddr;
          VirtualQueryEx(proc, p, &mInfo, sizeof(mInfo)) == sizeof(mInfo) &&
          p < (me.modBaseAddr + me.modBaseSize);
          p += mInfo.RegionSize) {
          Row r;
          r["pid"] = INTEGER(pid);
          std::stringstream ssStart;
          ssStart << std::hex << mInfo.BaseAddress;
          r["start"] = "0x" + ssStart.str();
          std::stringstream ssEnd;
          ssEnd << std::hex << std::setfill('0') << std::setw(16)
            << reinterpret_cast<unsigned long long>(mInfo.BaseAddress) +
            mInfo.RegionSize;
          r["end"] = "0x" + ssEnd.str();
          r["permissions"] = formatMemPerms(mInfo.Protect);
          r["offset"] =
            BIGINT(reinterpret_cast<unsigned long long>(mInfo.AllocationBase));
          r["device"] = "-1";
          r["inode"] = INTEGER(-1);
          r["path"] = me.szExePath;
          r["pseudo"] = INTEGER(-1);
          results.push_back(r);
        }
        ret = Module32Next(modSnap, &me);
      }
      CloseHandle(proc);
      CloseHandle(modSnap);
      return Status(0, "Ok");
    }

    /// Helper function for enumerating all active processes on the system
    Status getProcList(std::set<long>& pids) {
      auto procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if (procSnap == INVALID_HANDLE_VALUE) {
        return Status(1, "Failed to open process snapshot");
      }

      PROCESSENTRY32 procEntry;
      procEntry.dwSize = sizeof(PROCESSENTRY32);
      auto ret = Process32First(procSnap, &procEntry);

      if (ret == FALSE) {
        CloseHandle(procSnap);
        return Status(1, "Failed to open first process");
      }

      while (ret != FALSE) {
        pids.insert(procEntry.th32ProcessID);
        ret = Process32Next(procSnap, &procEntry);
      }

      CloseHandle(procSnap);
      return Status(0, "Ok");
    }

    void genProcess(const WmiResultItem& result, QueryData& results_data) {

      long pid;
      Row r;
      Status s;
      s = result.GetLong("ProcessId", pid);
      r["pid"] = s.ok() ? BIGINT(pid) : BIGINT(-1);

      long uid = -1;
      long gid = -1;
      HANDLE hprocess = nullptr;

      /// Store current process pid for more efficient API use.
      auto current_pid = GetCurrentProcessId();
      if (pid == current_pid) {
        hprocess = GetCurrentProcess();
      }
      else {
        hprocess =
          OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
      }

      if (GetLastError() == ERROR_ACCESS_DENIED) {
        uid = 0;
        gid = 0;
      }

      result.GetString("Name", r["name"]);
      result.GetString("ExecutablePath", r["path"]);
      result.GetString("CommandLine", r["cmdline"]);
      result.GetString("ExecutionState", r["state"]);

      long l_holder;
      result.GetLong("ParentProcessId", l_holder);
      r["parent"] = BIGINT(l_holder);
      result.GetLong("Priority", l_holder);
      r["nice"] = INTEGER(l_holder);
      r["on_disk"] = osquery::pathExists(r["path"]).toString();
      result.GetLong("ThreadCount", l_holder);
      r["threads"] = INTEGER(l_holder);

      std::string s_holder;
      result.GetString("PrivatePageCount", s_holder);
      r["wired_size"] = BIGINT(s_holder);
      result.GetString("WorkingSetSize", s_holder);
      r["resident_size"] = s_holder;
      result.GetString("VirtualSize", s_holder);
      r["total_size"] = BIGINT(s_holder);

      std::string file_name(MAX_PATH, '\0');
      if (pid == current_pid) {
        GetModuleFileName(nullptr, &file_name.front(), MAX_PATH);
      }
      else {
        GetModuleFileNameEx(hprocess, nullptr, &file_name.front(), MAX_PATH);
      }

      r["cwd"] = file_name;
      r["root"] = r["cwd"];

      r["pgroup"] = "-1";
      r["euid"] = "-1";
      r["suid"] = "-1";
      r["egid"] = "-1";
      r["sgid"] = "-1";

      FILETIME create_time;
      FILETIME exit_time;
      FILETIME kernel_time;
      FILETIME user_time;
      auto proc_ret =
        GetProcessTimes(hprocess, &create_time, &exit_time, &kernel_time, &user_time);
      if (proc_ret == FALSE) {
        r["user_time"] = BIGINT(-1);
        r["system_time"] = BIGINT(-1);
        r["start_time"] = BIGINT(-1);
      }
      else {
        // Windows stores proc times in 100 nanosecond ticks
        ULARGE_INTEGER utime;
        utime.HighPart = user_time.dwHighDateTime;
        utime.LowPart = user_time.dwLowDateTime;
        r["user_time"] = BIGINT(utime.QuadPart / 10000);
        utime.HighPart = kernel_time.dwHighDateTime;
        utime.LowPart = kernel_time.dwLowDateTime;
        r["system_time"] = BIGINT(utime.QuadPart / 10000);
        r["start_time"] = BIGINT(osquery::filetimeToUnixtime(create_time));
      }

      /// Get the process UID and GID from its SID
      HANDLE tok = nullptr;
      std::vector<char> tok_user(sizeof(TOKEN_USER), 0x0);
      auto ret = OpenProcessToken(hprocess, TOKEN_READ, &tok);
      if (ret != 0 && tok != nullptr) {
        unsigned long tok_owner_buff_len;
        ret = GetTokenInformation(tok, TokenUser, nullptr, 0, &tok_owner_buff_len);
        if (ret == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
          tok_user.resize(tok_owner_buff_len);
          ret = GetTokenInformation(
            tok, TokenUser, tok_user.data(), tok_owner_buff_len, &tok_owner_buff_len);
        }

        // Check if the process is using an elevated token
        auto elevated = FALSE;
        TOKEN_ELEVATION Elevation;
        DWORD cb_size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(
          tok, TokenElevation, &Elevation, sizeof(Elevation), &cb_size)) {
          elevated = Elevation.TokenIsElevated;
        }

        r["is_elevated_token"] = elevated ? INTEGER(1) : INTEGER(0);
      }
      if (uid != 0 && ret != 0 && !tok_user.empty()) {
        auto sid = PTOKEN_OWNER(tok_user.data())->Owner;
        r["uid"] = INTEGER(getUidFromSid(sid));
        r["gid"] = INTEGER(getGidFromSid(sid));
      }
      else {
        r["uid"] = INTEGER(uid);
        r["gid"] = INTEGER(gid);
      }

      if (hprocess != nullptr) {
        CloseHandle(hprocess);
      }
      if (tok != nullptr) {
        CloseHandle(tok);
        tok = nullptr;
      }
      results_data.push_back(r);
    }

    QueryData genProcesses(QueryContext& context) {
      QueryData results;

      std::string query = "SELECT ProcessId FROM Win32_Process";

      //std::unordered_set<long> pid_list;
      std::unordered_set<std::string> wmi_constraints;
      auto pid_iter = context.constraints.find("pid");
      if (pid_iter != context.constraints.end() &&
        pid_iter->second.exists(EQUALS)) {
        for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
          //pid_list.insert(pid);
          wmi_constraints.insert("ProcessId=" + std::to_string(pid));
        }

        if (!wmi_constraints.empty()) {
          query += " WHERE " + boost::algorithm::join(wmi_constraints, " OR ");
        }
      }

      WmiRequest request(query);
      if (!request.getStatus().ok()) {
        VLOG(1) << "Failed to enumerate processes from WMI query";
        return results;
      }

      for (const auto& item : request.results()) {
        genProcess(item, results);
      }

      return results;
    }

    QueryData genProcessMemoryMap(QueryContext& context) {
      QueryData results;

      std::unordered_set<long> pidlist;
      auto pid_iter = context.constraints.find("pid");
      if (pid_iter != context.constraints.end() &&
        pid_iter->second.exists(EQUALS)) {
        for (const auto& pid : context.constraints.at("pid").getAll<int>(EQUALS)) {
          pidlist.insert(pid);
        }
      }

      for (const auto& pid : pidlist) {
        auto s = genMemoryMap(pid, results);
        if (!s.ok()) {
          VLOG(1) << s.getMessage();
        }
      }

      return results;
    }

  } // namespace tables
} // namespace osquery

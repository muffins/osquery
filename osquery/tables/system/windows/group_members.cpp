/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"
#include "osquery/core/conversions.h"

namespace osquery {

std::string psidToString(PSID sid);

namespace tables {

void processLocalGroupMembers(QueryData& results,
                              std::string ugid,
                              std::string group) {
  unsigned long dwGroupMemberInfoLevel = 2;
  unsigned long dwNumGroupMembersRead = 0;
  unsigned long dwTotalGroupMembers = 0;
  unsigned long ret = 0;
  LOCALGROUP_MEMBERS_INFO_2* lgminfo = nullptr;

  do {
    ret = NetLocalGroupGetMembers(nullptr,
                                  stringToWstring(group).c_str(),
                                  dwGroupMemberInfoLevel,
                                  (LPBYTE*)&lgminfo,
                                  MAX_PREFERRED_LENGTH,
                                  &dwNumGroupMembersRead,
                                  &dwTotalGroupMembers,
                                  nullptr);

    if (ret == NERR_Success || ret == ERROR_MORE_DATA) {
      if (lgminfo != nullptr) {
        for (size_t i = 0; i < dwNumGroupMembersRead; i++) {
          Row r;

          r["ugid"] = ugid;
          r["uuid"] = psidToString(lgminfo[i].lgrmi2_sid);
          r["groupname"] = group;
          r["member"] = wstringToString(lgminfo[i].lgrmi2_domainandname);

          switch (lgminfo[i].lgrmi2_sidusage) {
          case SidTypeUser:
            r["type"] = "User";
            break;
          case SidTypeGroup:
            r["type"] = "Group";
            break;
          case SidTypeWellKnownGroup:
            r["type"] = "Well-known";
            break;
          case SidTypeDeletedAccount:
            r["type"] = "Deleted";
            break;
          case SidTypeUnknown:
          default:
            r["type"] = "Unknown";
            break;
          }

          results.push_back(r);
        }
      }
    } else {
      LOG(WARNING) << "NetLocalGroupGetMembers failed with " << ret;
    }
    if (lgminfo != nullptr) {
      NetApiBufferFree(lgminfo);
    }

  } while (ret == ERROR_MORE_DATA);
}

QueryData genGroupMembers(QueryContext& context) {
  QueryData results;

  SQL sql("SELECT ugid, groupname FROM groups");
  if (!sql.ok()) {
    LOG(WARNING) << sql.getStatus().getMessage();
  }

  for (auto r : sql.rows())
    processLocalGroupMembers(results, r["ugid"], r["groupname"]);

  return results;
}
}
}

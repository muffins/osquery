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

void GetSid(LPCWSTR wszAccName, PSID* ppSid);

void processLocalUserGroups(QueryData& results,
                            std::string uuid,
                            std::string user) {
  unsigned long dwUserGroupInfoLevel = 0;
  unsigned long dwNumUserGroupsRead = 0;
  unsigned long dwTotalUserGroupMembers = 0;
  unsigned long ret = 0;
  LOCALGROUP_USERS_INFO_0* ulginfo = nullptr;
  PSID sid = nullptr;
  do {
    ret = NetUserGetLocalGroups(nullptr,
                                stringToWstring(user).c_str(),
                                dwUserGroupInfoLevel,
                                1,
                                (LPBYTE*)&ulginfo,
                                MAX_PREFERRED_LENGTH,
                                &dwNumUserGroupsRead,
                                &dwTotalUserGroupMembers);

    if (ret == NERR_Success || ret == ERROR_MORE_DATA) {
      if (ulginfo != nullptr) {
        for (size_t i = 0; i < dwNumUserGroupsRead; i++) {
          Row r;
          GetSid(ulginfo[i].lgrui0_name, &sid);

          r["uuid"] = uuid;
          r["ugid"] = psidToString(sid);
          r["username"] = user;
          r["groupname"] = wstringToString(ulginfo[i].lgrui0_name);

          results.push_back(r);
        }
      }
    } else {
      LOG(WARNING) << user << " NetUserGetLocalGroups failed with " << ret;
    }
    if (ulginfo != nullptr) {
      NetApiBufferFree(ulginfo);
    }

  } while (ret == ERROR_MORE_DATA);
}

QueryData genUserGroups(QueryContext& context) {
  QueryData results;

  SQL sql(
      "SELECT uuid, username FROM users WHERE username NOT IN ('SYSTEM', "
      "'LOCAL SERVICE', 'NETWORK SERVICE')");
  if (!sql.ok()) {
    LOG(WARNING) << sql.getStatus().getMessage();
  }

  for (auto r : sql.rows())
    processLocalUserGroups(results, r["uuid"], r["username"]);

  return results;
}
}
}

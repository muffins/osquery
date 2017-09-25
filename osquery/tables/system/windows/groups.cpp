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

#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/tables/system/windows/registry.h"
#include "osquery/core/conversions.h"

namespace osquery {

std::string psidToString(PSID sid);

namespace tables {

void GetSid(LPCWSTR wszAccName, PSID* ppSid) {
  // Validate the input parameters.
  if (wszAccName == NULL || ppSid == NULL) {
    return;
  }

  // Create buffers that may be large enough.
  // If a buffer is too small, the count parameter will be set to the size
  // needed.
  const DWORD INITIAL_SIZE = 32;
  DWORD cbSid = 0;
  DWORD dwSidBufferSize = INITIAL_SIZE;
  DWORD cchDomainName = 0;
  DWORD dwDomainBufferSize = INITIAL_SIZE;
  WCHAR* wszDomainName = NULL;
  SID_NAME_USE eSidType;
  DWORD dwErrorCode = 0;

  // Create buffers for the SID and the domain name.
  *ppSid = (PSID) new BYTE[dwSidBufferSize];
  if (*ppSid == NULL) {
    return;
  }
  memset(*ppSid, 0, dwSidBufferSize);
  wszDomainName = new WCHAR[dwDomainBufferSize];
  if (wszDomainName == NULL) {
    return;
  }
  memset(wszDomainName, 0, dwDomainBufferSize * sizeof(WCHAR));

  // Obtain the SID for the account name passed.
  for (;;) {
    // Set the count variables to the buffer sizes and retrieve the SID.
    cbSid = dwSidBufferSize;
    cchDomainName = dwDomainBufferSize;
    if (LookupAccountNameW(NULL, // Computer name. NULL for the local computer
                           wszAccName,
                           *ppSid, // Pointer to the SID buffer. Use NULL to get
                                   // the size needed,
                           &cbSid, // Size of the SID buffer needed.
                           wszDomainName, // wszDomainName,
                           &cchDomainName,
                           &eSidType)) {
      if (IsValidSid(*ppSid) == FALSE) {
        wprintf(L"The SID for %s is invalid.\n", wszAccName);
      }
      break;
    }
    dwErrorCode = GetLastError();

    // Check if one of the buffers was too small.
    if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER) {
      if (cbSid > dwSidBufferSize) {
        // Reallocate memory for the SID buffer.
        wprintf(L"The SID buffer was too small. It will be reallocated.\n");
        FreeSid(*ppSid);
        *ppSid = (PSID) new BYTE[cbSid];
        if (*ppSid == NULL) {
          return;
        }
        memset(*ppSid, 0, cbSid);
        dwSidBufferSize = cbSid;
      }
      if (cchDomainName > dwDomainBufferSize) {
        // Reallocate memory for the domain name buffer.
        wprintf(
            L"The domain name buffer was too small. It will be reallocated.\n");
        delete[] wszDomainName;
        wszDomainName = new WCHAR[cchDomainName];
        if (wszDomainName == NULL) {
          return;
        }
        memset(wszDomainName, 0, cchDomainName * sizeof(WCHAR));
        dwDomainBufferSize = cchDomainName;
      }
    } else {
      wprintf(L"LookupAccountNameW failed. GetLastError returned: %d\n",
              dwErrorCode);
      break;
    }
  }

  delete[] wszDomainName;
  return;
}

void processLocalGroups(QueryData& results) {
  unsigned long dwGroupInfoLevel = 1;
  unsigned long dwNumGroupsRead = 0;
  unsigned long dwTotalGroups = 0;
  unsigned long resumeHandle = 0;
  unsigned long ret = 0;
  LOCALGROUP_INFO_1* lginfo = nullptr;
  PSID sid;
  do {
    ret = NetLocalGroupEnum(nullptr,
                            dwGroupInfoLevel,
                            (LPBYTE*)&lginfo,
                            MAX_PREFERRED_LENGTH,
                            &dwNumGroupsRead,
                            &dwTotalGroups,
                            NULL);

    if ((ret == NERR_Success || ret == ERROR_MORE_DATA) && lginfo != nullptr) {
      for (size_t i = 0; i < dwNumGroupsRead; i++) {
        Row r;
        GetSid(lginfo[i].lgrpi1_name, &sid);

        r["ugid"] = psidToString(sid);
        r["groupname"] = wstringToString(lginfo[i].lgrpi1_name);
        r["comment"] = wstringToString(lginfo[i].lgrpi1_comment);
        results.push_back(r);
      }
    } else {
      LOG(WARNING) << "NetLocalGroupEnum failed with " << ret;
    }
    if (lginfo != nullptr) {
      NetApiBufferFree(lginfo);
    }

  } while (ret == ERROR_MORE_DATA);
}

QueryData genGroups(QueryContext& context) {
  QueryData results;

  processLocalGroups(results);

  return results;
}
}
}

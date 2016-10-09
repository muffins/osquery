/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

QueryData genPlatformInfo(QueryContext& context) {
  QueryData results;

  std::string query =
      "select Manufacturer, SMBIOSBIOSVersion, ReleaseDate, "
      "SystemBiosMajorVersion, SystemBiosMinorVersion from Win32_BIOS";
  WmiRequest request(query);
  if (!request.getStatus().ok()) {
    return results;
  }
  std::vector<WmiResultItem>& wmiResults = request.results();
  if (wmiResults.size() != 1) {
    return results;
  }
  Row r;
  std::string sPlaceholder;
  wmiResults[0].GetString("Manufacturer", r["vendor"]);
  wmiResults[0].GetString("SMBIOSBIOSVersion", r["version"]);
  wmiResults[0].GetString("ReleaseData", r["date"]);
  std::string majorRevision;
  wmiResults[0].GetString("SystemBiosMajorVersion", majorRevision);
  std::string minorRevision;
  wmiResults[0].GetString("SystemBiosMinorVersion", minorRevision);
  if (!majorRevision.empty() && !minorRevision.empty()) {
    r["revision"] = majorRevision + "." + minorRevision;
  }

  std::string biosQuery =
      "select StartingAddress, EndingAddress from CIM_BIOSLoadedInNV";
  WmiRequest biosRequest(biosQuery);
  if (!biosRequest.getStatus().ok()) {
    return results;
  }
  std::vector<WmiResultItem>& biosResults = biosRequest.results();
  if (biosResults.size() != 1) {
    return results;
  }
  long long sAddress, eAddress;
  biosResults[0].GetLongLong("StartingAddress", sAddress);
  biosResults[0].GetLongLong("EndingAddress", eAddress);

  r["address"] = SQL_TEXT(sAddress);
  r["size"] = SQL_TEXT(eAddress - sAddress);

  results.push_back(r);
  return results;
}
}
}

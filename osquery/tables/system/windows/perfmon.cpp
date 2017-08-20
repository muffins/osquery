/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#include <Pdh.h>

#include <osquery/tables.h>
#include <osquery/logger.h>

namespace osquery {
namespace tables {

QueryData genPerfMon(QueryContext& context) {

  QueryData results;
  std::string counterQuery {"\\Process(*)\\% Processor Time"};

  HQUERY queryHandle;
  //unsigned long queryData;
  PdhOpenQuery(0, 0, &queryHandle);

  HCOUNTER counter = nullptr;
  PdhAddCounter(queryHandle,
                counterQuery.c_str(),
                0,
                &counter);

  auto ret = PdhCollectQueryData(queryHandle);
  if (ret != ERROR_SUCCESS) {
    VLOG(1) << "[+] Collect Query Data failed with " << ret;
    return results;
  }

  //PDH_RAW_COUNTER val;
  //ret = PdhGetRawCounterValue(counter, );

  PDH_FMT_COUNTERVALUE fmtVal;
  ret = PdhGetFormattedCounterValue(
          counter,
          PDH_FMT_LONG,
          nullptr,
          &fmtVal
        );

  if (ret != ERROR_SUCCESS) {
    VLOG(1) << "[+] Get Formatted Value failed with " << ret;
    return results;
  }


  PdhCloseQuery(queryHandle);
  return results;
}
}
}

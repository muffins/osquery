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
#include <sstream>

#include <stdlib.h>

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/windows/system_util.h"

namespace osquery {
namespace tables {

void genInterfaces(QueryData& results_data) {
  std::stringstream ss;
  ss << "SELECT * FROM win32_networkadapterconfiguration where IPEnabled=TRUE";

  WmiRequest request(ss.str());
  if (request.ok()) {
    std::vector<WmiResultItem> &results = request.results();
	for (const auto& result : results) {
		Row r;
		r["address"] = SQL_TEXT(result.GetString("DefaultIPGateway"));
		r["ip_subnet"] = SQL_TEXT(result.GetString("DHCPEnabled"));
		r["serivce_name"] = SQL_TEXT(result.GetString("Description"));
		results_data.push_back(r);
	}
  }
}

QueryData genWinInterfacesAddresses(QueryContext& context) {
  QueryData results;
  genInterfaces(results);

  return results;
}
}
}

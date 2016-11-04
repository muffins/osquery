/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/system.h>

#include "osquery/core/json.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {
const std::string kAcquisitionQueryPrefix = "acquisition.";

QueryData genAcquisition(QueryContext& context) {
  QueryData results;

  std::vector<std::string> acquisition_paths;
  scanDatabaseKeys(kQueries, acquisition_paths, kAcquisitionQueryPrefix);
  for (const auto& key : acquisition_paths){
    Row r;
    std::string json;
    pt::ptree tree;
    getDatabaseValue(kQueries, key, json);
    try {
      std::stringstream ss(json);
      pt::read_json(ss, tree);
    } catch (const pt::ptree_error& e) {
      return results;
    }
    r["guid"] = SQL_TEXT(key.substr(kAcquisitionQueryPrefix.size()));
    r["location"] = SQL_TEXT(tree.get<std::string>("location"));
    r["type"] = SQL_TEXT(tree.get<std::string>("type"));
    r["size"] = INTEGER(tree.get<int>("size"));
    r["status"] = SQL_TEXT(tree.get<std::string>("status"));
    if(r["status"] == "COMPLETED") {
        r["time"] = INTEGER(tree.get<int>("start_time"));
    } else {
      r["time"] = INTEGER(getUnixTime() - tree.get<int>("start_time"));
    }
    results.push_back(r);
  }
  return results;
}
}
}

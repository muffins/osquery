/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 #include <sys/stat.h>

 #include <boost/filesystem.hpp>
 #include <boost/uuid/uuid.hpp>
 #include <boost/uuid/uuid_generators.hpp>
 #include <boost/uuid/uuid_io.hpp>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {
const std::string kAcquisitionQueryPrefix = "acquisition.";

void scheduleMemoryAcquisition(const std::string strpid, QueryData& results) {
  unsigned long pid;
  Status stat = safeStrtoul(strpid, 10, pid);
  if(!stat.ok()) {
    return;
  }
  Row r;
  std::string uuid = boost::uuids::to_string(boost::uuids::random_generator()());
  r["guid"] = SQL_TEXT(uuid);
  r["pid"] = BIGINT(pid);
  r["size"] = BIGINT(-1);
  r["status"] = SQL_TEXT("PENDING");
  r["time"] = BIGINT(0);
  pt::ptree tree;
  tree.put("location", pid);
  tree.put("status", "PENDING");
  tree.put("size", -1);
  tree.put("start_time", getUnixTime());
  tree.put("type", "PROCESS_MEMORY");

  std::ostringstream os;
  pt::write_json(os, tree, false);
  setDatabaseValue(kQueries, kAcquisitionQueryPrefix+uuid, os.str());
  results.push_back(r);
}

QueryData genAcquireMemory(QueryContext& context) {
  QueryData results;

  auto pids = context.constraints["pid"].getAll(EQUALS);
  context.expandConstraints(
      "pid",
      LIKE,
      pids,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        pids.insert(pattern);
        return Status(0);
      }));

  for (const auto& pid : pids){
    scheduleMemoryAcquisition(pid, results);
  }

  return results;
}
}
}

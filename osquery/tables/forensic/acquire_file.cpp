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
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/json.h"

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {
const std::string kAcquisitionQueryPrefix = "acquisition.";

void scheduleFileAcquisition(const fs::path& path, QueryData& results) {
// Must provide the path, filename, directory separate from boost path->string
// helpers to match any explicit (query-parsed) predicate constraints.
#if !defined(WIN32)
  // On POSIX systems, first check the link state.
  struct stat link_stat;
  if (lstat(path.string().c_str(), &link_stat) < 0) {
    // Path was not real, had too may links, or could not be accessed.
    return;
  }
#endif

  struct stat file_stat;
  if (stat(path.string().c_str(), &file_stat)) {
    // Path was not real, had too may links, or could not be accessed.
    return;
  }

  Row r;
  std::string uuid =
      boost::uuids::to_string(boost::uuids::random_generator()());
  r["guid"] = SQL_TEXT(uuid);
  r["path"] = SQL_TEXT(path.string());
  r["size"] = BIGINT(file_stat.st_size);
  r["status"] = SQL_TEXT("PENDING");
  r["time"] = BIGINT(0);
  pt::ptree tree;
  tree.put("location", path.string());
  tree.put("status", "PENDING");
  tree.put("size", file_stat.st_size);
  tree.put("start_time", getUnixTime());
  tree.put("type", "FILE");

  std::ostringstream os;
  pt::write_json(os, tree, false);
  setDatabaseValue(kQueries, kAcquisitionQueryPrefix + uuid, os.str());
  results.push_back(r);
}

QueryData genAcquireFile(QueryContext& context) {
  QueryData results;

  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // Iterate through each of the resolved/supplied paths.
  for (const auto& path_string : paths) {
    fs::path path = path_string;
    scheduleFileAcquisition(path, results);
  }

  return results;
}
}
}

/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// Location of crash logs on Ubuntu
const std::string kDiagnosticReportsPath = "/var/crashes";

void readCrashDump(const std::string& app_log, Row& r) {}

QueryData genCrashLogs(QueryContext& context) {
  QueryData results;

  return results;
}
}
}

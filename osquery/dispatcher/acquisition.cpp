/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/system.h>
#include <osquery/acquisition.h>

#include "osquery/core/conversions.h"
#include "osquery/dispatcher/acquisition.h"

namespace osquery {

FLAG(uint64,
     max_carve_size,
     4194304,
     "Maximum size (in bytes) the acquisition engine will attempt to carve"
     "(Default is 4KB).")

FLAG(uint64,
     acquisition_interval,
     10,
     "Seconds between polling for new queries (default 10)")

DECLARE_bool(disable_acquisition);

const size_t kAcquisitionAccelerationInterval = 5;

void AcquisitionRunner::start() {

  while (!interrupted()) {
    Acquisition::instance().getPendingFileCarves();
    Acquisition::instance().executePendingFileCarves();

    std::string str_acu = "0";
    Status database = getDatabaseValue(
        kPersistentSettings, "acquisition_accelerate_checkins_expire", str_acu);

    unsigned long accelerate_checkins_expire;
    Status conversion = safeStrtoul(str_acu, 10, accelerate_checkins_expire);
    if (!database.ok() || !conversion.ok() ||
        getUnixTime() > accelerate_checkins_expire) {
      pauseMilli(FLAGS_acquisition_interval * 1000);
    } else {
      pauseMilli(kAcquisitionAccelerationInterval * 1000);
    }
  }
}

Status startAcquisition() {
  if (!FLAGS_disable_acquisition) {
    Dispatcher::addService(std::make_shared<AcquisitionRunner>());
    return Status(0, "OK");
  } else {
    return Status(1, "Acquisition service not enabled.");
  }
}
}

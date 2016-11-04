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
#include <osquery/sql.h>

#include "osquery/acquisition/acquisition.h"
#include "osquery/core/json.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool,
     disable_acquisition,
     false, // TODO: Changeme when done.
     "Disable acuisition engine (default true)");

void Acquisition::getPendingFileCarves() {
  pendingCarves_.clear();
  pendingCarves_ =
      SQL::selectAllFrom("acquire_file", "status", EQUALS, "PENDING");
}

void Acquisition::executePendingFileCarves() {
  if (pendingCarves_.size() == 0) {
    return;
  }

  for (auto& r : pendingCarves_) {
    // TODO: Consider creating the GUID of each Carve task here.
    Status s = carveFile(r["path"]);
    if (!s.ok()) {
      continue;
    }
    // Update the value in the database
    pt::ptree tree;
    tree.put("location", r["path"]);
    // TODO: Consider adding a 'FAILED' status?
    tree.put("status", "COMPLETE");
    tree.put("size", r["size"]);
    tree.put("start_time", r["start_time"]);
    tree.put("type", r["type"]);

    std::ostringstream os;
    pt::write_json(os, tree, false);
    setDatabaseValue(kQueries, acquisitionPrefix_ + r["guid"], os.str());
  }
}

// TODO: Error handling around creation of FS
// TODO: Make FS not be a temp file.
Status Acquisition::makeAcquisitionFS() {
  if (!fs::exists(acquisitionStore_)) {
    bool ret = fs::create_directory(acquisitionStore_);
    if (!ret) {
      return Status(1, "Failed to create Acquisition Store");
    }
  }
  return fs::exists(acquisitionStore_)
             ? Status(0, "OK")
             : Status(1, "Failed to create Acquisition Store");
}

/**
 * Note:
 * When we get to the point of carving memory or carving directory structures
 * we could think about creating a folder 'GUID' underneath the osquery FS,
 * and then write out everything by it's root name there.  For directories
 * this might just mean recreating the dir structure underneath the guid
 * folder.
 */
// TODO: This needs error handling
// TODO: This needs actual carving.
Status Acquisition::carveFile(fs::path p) {
  std::ifstream source(p.string(), std::ios::binary);
  std::ofstream dest((acquisitionStore_ / p.filename()).string(),
                     std::ios::binary);

  // "Carve" the file.
  dest << source.rdbuf();

  source.close();
  dest.close();

  return Status(0, "OK");
}

Status Acquisition::carveMemory() {
  return Status(0, "OK");
}
}

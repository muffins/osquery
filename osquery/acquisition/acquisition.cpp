/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/acquisition.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool,
     disable_acquisition,
     false,
     "Disable acquisition engine (default false)");

CREATE_REGISTRY(AcquisitionPlugin, "acquisition");

FLAG(string, acquisition_plugin, "tls", "Acquisition plugin name");

Status AcquisitionPlugin::call(const PluginRequest& request,
                               PluginResponse& response) {
  if (request.count("action") == 0) {
    return Status(1, "Acquisition plugins require an action in PluginRequest");
  }

  if (request.at("action") == "sendCarves") {
    return Status(0, "OK");
  }
  return Status(1,
                "Acquisition plugin action unknown: " + request.at("action"));
}

Acquisition::Acquisition() {
  Status s = makeAcquisitionFS();
}

Status Acquisition::getPendingFileCarves() {
  pendingCarves_.clear();
  std::vector<std::string> fileAcquisitions;
  scanDatabaseKeys(kQueries, fileAcquisitions, acquisitionPrefix_);

  for (const auto& key : fileAcquisitions) {
    std::string json;
    pt::ptree tree;
    getDatabaseValue(kQueries, key, json);
    try {
      std::stringstream ss(json);
      pt::read_json(ss, tree);
    } catch (const pt::ptree_error& e) {
      return;
    }
    if (tree.get<std::string>("status") != "PENDING") {
      continue;
    }
    Row r;
    r["guid"] = key.substr(acquisitionPrefix_.size());
    r["location"] = SQL_TEXT(tree.get<std::string>("location"));
    r["type"] = SQL_TEXT(tree.get<std::string>("type"));
    r["size"] = INTEGER(tree.get<int>("size"));
    r["status"] = SQL_TEXT(tree.get<std::string>("status"));
    pendingCarves_.push_back(r);
  }

  pendingCarves_ =
      SQL::selectAllFrom("acquisitions", "status", EQUALS, "PENDING");
}

Status Acquisition::updateCarveStatus(std::string status, std::string guid) {
  // There should only be one, as this function only updates the status of
  // a single carve.
  std::vector<std::string> carveTasks;
  scanDatabaseKeys(kQueries, fileAcquisitions, acquisitionPrefix_);
  return Status(0, "OK");
}

Status Acquisition::executePendingFileCarves() {
  if (pendingCarves_.size() == 0) {
    return;
  }

  for (auto& r : pendingCarves_) {
    // TODO: Consider creating the GUID of each Carve task here.
    Status s = carveFile(r["location"]);
    if (!s.ok()) {
      continue;
    }
    updateCarveStatus("COMPLETE", r["guid"]);
    // Update the value in the database
    pt::ptree tree;
    tree.put("location", r["location"]);
    // TODO: Consider adding a 'FAILED' status?
    tree.put("status", "COMPLETE");
    tree.put("size", r["size"]);
    tree.put("start_time", r["start_time"]);
    tree.put("type", r["type"]);

    std::ostringstream os;
    pt::write_json(os, tree, false);
    setDatabaseValue(kQueries, acquisitionPrefix_ + r["guid"], os.str());
  }
  return Status(0, "OK");
}

// TODO: Error handling around creation of FS, if it can't create,
// shutdown.
// TODO: Make FS not be a temp file.
Status Acquisition::makeAcquisitionFS() {
  if (!fs::exists(acquisitionStore_)) {
    bool ret = fs::create_directory(acquisitionStore_);
    if (!ret) {
      return Status(1, "Failed to create Acquisition Store");
    }
  }
  return Status(0, "OK");
}

/**
 * Note:
 * When we get to the point of carving memory or carving directory
 * structures
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

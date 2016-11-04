/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <queue>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/status.h>

namespace fs = boost::filesystem;

namespace osquery {

class AcquisitionPlugin : public Plugin {
 public:
  virtual Status sendAcquisitions() = 0;

  /// Main entrypoint for distirbuted plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

class Acquisition {
 public:
  /// Default constructor
  Acquisition();

  /// Default destructor
  ~Acquisition(){};

  /// Retrieve all pending file carve operations from the acquire_file table
  Status getPendingFileCarves();

  /// Executes all pending file carves
  Status executePendingFileCarves();

  /// Get a chunk of a carve
  Status getGuidChunk(const std::string& guid,
                      unsigned int chunk_number,
                      std::string& chunk);

  /// Helper function to return a row, given a GUID
  Row getRowByGuid(const std::string& guid);

  /// Helper function to update a row, given a GUID and the new row
  Status updateRowByGuid(const Row& r, const std::string& guid);

 private:
  const std::string acquisitionPrefix_ = "acquisition.";
  const fs::path acquisitionStore_ =
      fs::temp_directory_path() / std::string{"osquery-acquisitions"};
  QueryData pendingCarves_;
  std::queue<std::string> completedCarves_;

  /// Helper function to create the Acquisition FS
  Status makeAcquisitionFS();

  std::map<std::string, std::string> guidToMap(const std::string& guid);

  /**
   * @brief carves a specified file from the disk and stores it in the store
   *
   * Given a path to a file, this function will carve the file residing at
   * the path and store the result in the temp directory
   */
  Status carveFile(fs::path p);

  /**
   * @brief carves a specified file from the disk and stores it in the store
   *
   * Given a path to a file, this function will carve the file residing at
   * the path and store the result in the temp directory
   */
  Status carveMemory();
};
}

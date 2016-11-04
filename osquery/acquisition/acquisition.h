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

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <osquery/logger.h>

namespace fs = boost::filesystem;

namespace osquery {

class Acquisition {
 public:
  /// Default constructor
  Acquisition();

  /// Default destructor
  ~Acquisition(){};

  /// Retrieve all pending file carve operations from the acquire_file table
  void getPendingFileCarves();

  /// Executes all pending file carves
  void executePendingFileCarves();

 private:
  const std::string acquisitionPrefix_ = "acquisition.";
  const fs::path acquisitionStore_ = "/tmp/osquery-acq/";
  QueryData pendingCarves_;
  /// Helper function to create the Acquisition FS
  Status makeAcquisitionFS();

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

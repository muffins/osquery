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

#include <osquery/dispatcher.h>
#include <osquery/filesystem.h>

namespace osquery {

class Carver : public InternalRunnable {
 public:
  Carver(const std::set<std::string>& paths, const std::string& guid);

  ~Carver();

  /*
   * @brief A helper function to perform a start to finish carve
   *
   * This function walks through the carve, compress, and exfil functions
   * in one fell swoop. Use of this class should largely happen through
   * this function.
   */
  void start();

 protected:
  /*
   * @brief A helper function to 'carve' files from disk
   *
   * This function performs a "forensic carve" of a specified path to the
   * users tmp directory
   */
  Status carve(const boost::filesystem::path& path);
  /*
   * @brief A helper function to compress files in a specified directory
   *
   * Given a set of paths we bundle these into a tar archive. This file
   * will be a tgz, however currently no compression is performed.
   */
  Status compress(const std::set<boost::filesystem::path>& path);

  /*
   * @brief Helper function to exfil a file to the graph endpoint.
   *
   * Once all of the files have been carved and the tgz has been
   * created, we POST the carved file to an endpoint specified by the
   * carver_start_endpoint and carver_continue_endpoint
   */
  Status exfil(const boost::filesystem::path& path);

 private:
  /*
   * @brief a variable to keep track of the temp fs used in carving
   *
   * This variable represents the location in which we store all of our carved
   * files. When a carve has completed all of the desired files, as well
   * as the tar archive should reside in this directory
   */
  boost::filesystem::path carveDir_;

  /*
   * @brief a variable tracking all of the paths we attempt to carve
   *
   * This is a globbed set of file paths that we're expecting will be
   * carved.
   */
  std::set<boost::filesystem::path> carvePaths_;

  /*
   * @brief a helper variable for keeping track of the posix tar archive.
   *
   * This variable is the absolute location of the tar archive created from
   * tar'ing all of the carved files from the carve temp dir.
   */
  boost::filesystem::path archivePath_;

  /*
   * @brief a unique ID identifying the 'carve'
   *
   * This unique generated GUID is used to identify the carve session from
   * other carves. It is also used by our backend service to derive a
   * session key for exfiltration.
   */
  std::string carveGuid_;

  /*
   * @brief the uri used to begin POSTing carve data
   *
   * This endpoint should negotiate the details of the carve, as well
   * as give the client a session id used to continue POSTing the data.
   */
  std::string startUri_;

  /// The uri used to receive the data blocks of a carve
  std::string contUri_;

 private:
  friend class CarverTests;
};
}

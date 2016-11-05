/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// clang-format off
// This must be here to prevent a WinSock.h exists error
#include "osquery/remote/transports/tls.h"
// clang-format on

#include <vector>
#include <sstream>

#include <boost/property_tree/ptree.hpp>

#include <osquery/acquisition.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(string,
     acquisition_tls_write_endpoint,
     "",
     "TLS/HTTPS endpoint for acquisition results");

FLAG(uint64,
     acquisition_max_attempts,
     3,
     "Number of times to attempt sending an acquisition")

class TLSAcquisitionPlugin : public AcquisitionPlugin {
 public:
  Status setUp() override;
  Status sendAcquisitions() override;

 protected:
  std::string write_uri_;
};

REGISTER(TLSAcquisitionPlugin, "acquisition", "tls");

Status TLSAcquisitionPlugin::setUp() {
  write_uri_ = TLSRequestHelper::makeURI(FLAGS_acquisition_tls_write_endpoint);
  return Status(0, "OK");
}

Status TLSAcquisitionPlugin::sendAcquisitions() {
  std::string guid;
  while (true){
    guid = Acquisition::instance().guidToSend();
    if(guid == ""){break;}

  }
  return Status(0);
}
}

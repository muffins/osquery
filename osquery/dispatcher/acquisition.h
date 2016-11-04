/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#pragma once

namespace osquery {

/// An Acquisition service thread that implements the memory acquisition service
class AcquisitionRunner : public InternalRunnable {
 public:
  virtual ~AcquisitionRunner() {}
  AcquisitionRunner() {}

 public:
  /// The Acquisition thread entry point.
  void start();
};

Status startAcquisition();
}

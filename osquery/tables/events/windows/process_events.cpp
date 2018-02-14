/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_etw.h"
#include "osquery/filesystem/fileops.h"

namespace pt = boost::property_tree;

namespace osquery {

class WindowsProcessEventSubscriber
    : public EventSubscriber<WindowsEtwEventPublisher> {
 public:
  Status init() override {
    auto wc = createSubscriptionContext();

    // Set up the GUIDs to sunscribe to here
    /*
    for (auto& chan : osquery::split(FLAGS_windows_event_channels, ",")) {
      // We remove quotes if they exist
      boost::erase_all(chan, "\"");
      boost::erase_all(chan, "\'");
      wc->sources.insert(stringToWstring(chan));
    }
    */

    subscribe(&WindowsProcessEventSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(WindowsProcessEventSubscriber, "event_subscriber", "process_events");


Status WindowsProcessEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  FILETIME cTime;
  GetSystemTimeAsFileTime(&cTime);
  r["time"] = BIGINT(filetimeToUnixtime(cTime));

  return Status(0, "OK");
}
}

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/events/windows/windows_etw.h"
//#include "osquery/core/windows/wmi.h"
//#include "osquery/core/conversions.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {

// {55404E71 - 4DB9 - 4DEB - A5F5 - 8F86E46DDE56}
// Socket events, we can maybe go a level higher?
static const GUID kSocketEventsGuid = {
    0x55404E71,
    0x4DB9,
    0x4DEB,
    {0xA5, 0XF5, 0x8F, 0x86, 0xE4, 0x6D, 0xDE, 0x56}};

class WindowsEtwSocketSubscriber
    : public EventSubscriber<WindowsEtwEventPublisher> {
 public:
  Status init() override {
    auto wc = createSubscriptionContext();
    wc->guid = kSocketEventsGuid;
    subscribe(&WindowsEtwSocketSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(WindowsEtwSocketSubscriber,
         "event_subscriber",
         "windows_etw_socket_events");

Status WindowsEtwSocketSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  FILETIME cTime;
  GetSystemTimeAsFileTime(&cTime);
  r["time"] = BIGINT(filetimeToUnixtime(cTime));

  // TODO
  r["data"] = "";

  add(r);
  return Status(0, "OK");
}
}

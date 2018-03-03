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
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/windows/windows_etw.h"
//#include "osquery/core/windows/wmi.h"
//#include "osquery/core/conversions.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {

// {E53C6823-7BB8-44BB-90DC-3F86090D48A6}
// Socket events, we can maybe go a level higher?

const GUID kSocketEventsGuid = {
  0xE53C6823,
  0x7BB8,
  0x44BB,
  { 0x90, 0XDC, 0x3F, 0x86, 0x09, 0x0D, 0x48, 0xA6 } };

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

  r["timestamp"] = BIGINT(ec->timestamp);
  r["uptime"] = BIGINT(ec->uptime);
  r["remote_address"] = "";
  
  VLOG(1) << "Event - " << ec->eventId << " " << static_cast<int>(ec->level);

  for (const auto& kv : ec->eventData) {
    VLOG(1) << "Evt[" << kv.first << "] - " << kv.second;
  }

  r["data"] = "";

  add(r);
  return Status(0, "OK");
}
}

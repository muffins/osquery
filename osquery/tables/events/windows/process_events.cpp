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
#include <osquery/registry_factory.h>
#include <osquery/tables.h>

#include "osquery/events/windows/windows_etw.h"
//#include "osquery/core/windows/wmi.h"
//#include "osquery/core/conversions.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {

FLAG(bool,
     disable_process_events,
     true,
     "Enable the Windows process events subscriber.");

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
// Microsoft-Windows-Kernel-Process
const GUID kProcessEventsGuid = {
    0x22FB2CD6,
    0x0E7B,
    0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};

const std::string kProcessEventsTraceName{"osquery-process-events-etw-trace"};

// WINEVENT_KEYWORD_PROCESS = 0x10
const unsigned long kProcessEventsKeywords = 0x10;

class WindowsEtwProcessEventSubscriber
    : public EventSubscriber<WindowsEtwEventPublisher> {
 public:
  Status init() override {
    if (FLAGS_disable_process_events) {
      return Status(1, "Process event subscriber disabled via configuration");
    }

    auto wc = createSubscriptionContext();

    wc->guid = kProcessEventsGuid;
    wc->trace_name = kProcessEventsTraceName;
    wc->keywords = kProcessEventsKeywords;

    subscribe(&WindowsEtwProcessEventSubscriber::Callback, wc);
    return Status(0, "OK");
  }

  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(WindowsEtwProcessEventSubscriber,
         "event_subscriber",
         "process_events");

Status WindowsEtwProcessEventSubscriber::Callback(const ECRef& ec,
                                                  const SCRef& sc) {
  Row r;

  r["timestamp"] = BIGINT(ec->timestamp);

  auto pid = ec->eventData.find("ProcessID");
  const auto end = ec->eventData.end();
  r["pid"] = pid != end ? INTEGER((*pid).second) : "-1";

  auto path = ec->eventData.find("ImageName");
  r["path"] = path != end ? (*path).second : "-1";

  // Event ID 2 is a Process Stop Event
  if (ec->eventId == 2) {
    r["type"] = "stop";
    auto handles = ec->eventData.find("HandleCount");
    r["handles"] = handles != end ? INTEGER((*handles).second) : "-1";
    // TODO: Convert, might need changes to publisher
    //auto exit_time = ec->eventData.find("ExitTime");
    //r["exit_time"] = exit_time != end ? INTEGER((*exit_time).second) : "-1";

  } else if (ec->eventId == 1) {
    r["type"] = "start";
    auto parent = ec->eventData.find("ParentProcessID");
    r["parent"] = parent != end ? INTEGER((*parent).second) : "-1";
  }

  // For debugging purposes
  VLOG(1) << "Event - " << ec->eventId << " " << static_cast<int>(ec->level);
  for (const auto& kv : ec->eventData) {
    VLOG(1) << "Evt[" << kv.first << "] - " << kv.second;
  }

  add(r);
  return Status(0, "OK");
}
} // namespace osquery

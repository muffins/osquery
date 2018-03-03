/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#define _WIN32_DCOM

// Required for obtaining the event trace guid
#define INITGUID

// clang-format off
#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <tdh.h>
// clang-format on

#include <osquery/events.h>

namespace osquery {

/**
 * @brief Subscription details for Windows ETW Traces
 *
 * This context is specific to the Windows ETW traces.
 * Subscribers can pass a vector of source values indicating which
 * Windows event logs the subscriber wishes to subscribe to.
 */
struct WindowsEtwSubscriptionContext : public SubscriptionContext {
  /// The GUID of the ETW provider to which we'll subscribe
  GUID guid;

 private:
  friend class WindowsEtwEventPublisher;
};

/**
 * @brief Event details for WindowsEventLogEventPublisher events.
 *
 * It is the responsibility of the subscriber to understand the best
 * way in which to parse the event data. The publisher will convert the
 * Event Log record into a boost::property_tree, and return the tree to
 * the subscriber for further parsing and row population.
 */
struct WindowsEtwEventContext : public EventContext {
  /// Event Metadata associated with the record
  unsigned long pid;

  unsigned short eventId;

  unsigned char level;

  unsigned char channel;

  unsigned long long uptime;

  unsigned long long timestamp;

  /// Relevant event data
  std::map<std::string, std::string> eventData;

  /// GUID associated with the ETW trace provider
  GUID etwProviderGuid;
};

using WindowsEtwEventContextRef = std::shared_ptr<WindowsEtwEventContext>;
using WindowsEtwSubscriptionContextRef =
    std::shared_ptr<WindowsEtwSubscriptionContext>;

/**
 * @brief A Windows Event Log Publisher
 *
 * This EventPublisher allows EventSubscriber's to subscribe to Windows
 * Event Logs. By default we subscribe to all of the Windows system Event
 * Log channels, and make _no_ filter queries on the events returned by
 * the system, as any desired filtering should be handled at through SQL
 * queries.
 */
class WindowsEtwEventPublisher
    : public EventPublisher<WindowsEtwSubscriptionContext,
                            WindowsEtwEventContext> {
  DECLARE_PUBLISHER("windows_etw");

 public:
  /// Checks to see if a Event Log channel matches a given subscriber
  bool shouldFire(const WindowsEtwSubscriptionContextRef& mc,
                  const WindowsEtwEventContextRef& ec) const override;

  void configure() override;

  void tearDown() override;

  /// The calling for beginning the thread's run loop.
  Status run() override;

  /// Callback function for processing ETW record data
  /// Must be static to be handed off to the Windows API
  static bool WINAPI processEtwRecord(PEVENT_RECORD pEvent);

 private:
  /// Ensures that all Windows event log subscriptions are removed
  void stop() override;

  /// Returns whether or not the publisher has active subscriptions
  bool isSubscriptionActive() const;

 private:
  /// Vector of all provider GUIDs on which we'll begin traces
  std::vector<GUID> providerGuids_;

  /// Map of all GUIDs to handles for all event traces
  // std::map<GUID, TRACEHANDLE> etw_handles_;
  std::vector<std::pair<GUID, PTRACEHANDLE>> etw_handles_;

 public:
  friend class WindowsEtwTests;
  // FRIEND_TEST(WindowsEtwTests, test_register_event_pub);
};
}

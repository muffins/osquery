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
  /// Channel or Path of the Windows Event Log to subscribe to
  // std::set<std::wstring> sources;
  // The ETW Provicer GUID to subscribe to
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
  /// A Windows event log record converted from XML
  // boost::property_tree::ptree eventRecord;
  std::map<std::string, std::string> eventData;

  /*
   * In Windows event logs, the source to which an event belongs is referred
   * to as the 'channel'. We keep track of the channel for each event, as the
   * subscriber can decide to receive only events for specified channels.
   */
  // std::wstring channel;
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

  /*
  static unsigned long __stdcall winEventCallback(
      EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);

  /// Helper function to convert an XML event blob into a property tree
  static Status parseEvent(EVT_HANDLE evt,
                           boost::property_tree::ptree& propTree);
  */

  /// Windows Event Callback for ETW trace parsing
  // void WINAPI WindowsEtwEventPublisher::processEvent(PEVENT_RECORD pEvent);

 private:
  /// Ensures that all Windows event log subscriptions are removed
  void stop() override;

  /// Returns whether or not the publisher has active subscriptions
  bool isSubscriptionActive() const;

 private:
  /// Vector of all provider GUIDs on which we'll begin traces
  std::vector<GUID> providerGuids_;

  std::map<GUID, TRACEHANDLE> etw_handles_;

  /// Vector of all handles to windows event log publisher callbacks
  // std::vector<TRACEHANDLE> etw_handles_;

 public:
  friend class WindowsEtwTests;
  // FRIEND_TEST(WindowsEtwTests, test_register_event_pub);
};
}

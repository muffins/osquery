/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#define _WIN32_DCOM

#include <Windows.h>
#include <Evntrace.h>

// TODO: Assess if these are needed
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/tokenizer.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/events/windows/windows_etw.h"

namespace pt = boost::property_tree;

namespace osquery {

REGISTER(WindowsEtwEventPublisher, "event_publisher", "windows_etw");

const std::chrono::milliseconds kWinEventLogPause(200);

const std::wstring kOsqueryEtwSessionName = L"osquery etw trace session";

// GUID that identifies your trace session.
// Remember to create your own session GUID.

// {22377e0a-63b0-4f43-a824-4b3554ac8985}
static const GUID kOsquerySessionGuid =
{ 0x22377e0a, 0x63b0, 0x4f43, { 0xa8, 0x24, 0x4b, 0x35, 0x54, 0xac, 0x89, 0x85 } };

// GUID that identifies the provider that you want
// to enable to your session.

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID kProcEventsGuid =
{ 0x22fb2cd6, 0x0e7b, 0x4228, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

void WindowsEtwEventPublisher::configure() {

  stop();

  ULONG status = ERROR_SUCCESS;
  TRACEHANDLE SessionHandle = 0;
  EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
  ULONG BufferSize = 0;
  BOOL TraceOn = TRUE;


  /*
  for (auto& sub : subscriptions_) {

    auto sc = getSubscriptionContext(sub->context);

    for (const auto& chan : sc->sources) {
      // TODO: Registry for system registry events

      if (hSubscription == nullptr) {
        LOG(WARNING) << "Failed to subscribe to "
                     << wstringToString(chan.c_str()) << ": " << GetLastError();
      } else {
        win_event_handles_.push_back(hSubscription);

      }
    }

  }
  */
  BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH + sizeof(kOsqueryEtwSessionName);
  pSessionProperties = (EVENT_TRACE_PROPERTIES*) malloc(BufferSize);

  ZeroMemory(pSessionProperties, BufferSize);
  pSessionProperties->Wnode.BufferSize = BufferSize;
  pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
  pSessionProperties->Wnode.Guid = kProcEventsGuid;
  pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
  pSessionProperties->MaximumFileSize = 1;  // 1 MB
  pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + static_cast<unsigned long>(kOsqueryEtwSessionName.size());

  status = StartTrace((PTRACEHANDLE)&SessionHandle, (LPCSTR)kOsqueryEtwSessionName.c_str(), pSessionProperties);

  etw_handles_.push_back(SessionHandle);

  status = EnableTraceEx2(
    SessionHandle,
    (LPCGUID)&kProcEventsGuid,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    TRACE_LEVEL_INFORMATION,
    0,
    0,
    0,
    NULL
    );

}

Status WindowsEtwEventPublisher::run() {
  pause();
  return Status(0, "OK");
}

void WindowsEtwEventPublisher::stop() {
  for (auto& e : etw_handles_) {

    ULONG status = 0;
    ULONG BufferSize = 0;
    EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*) malloc(BufferSize);

    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Guid = kProcEventsGuid;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + static_cast<unsigned long>(kOsqueryEtwSessionName.size());

    if (e != 0) {
      status = ControlTrace(e, (LPSTR)kOsqueryEtwSessionName.c_str(), pSessionProperties, EVENT_TRACE_CONTROL_STOP);
    }

  }
  etw_handles_.clear();
}

void WindowsEtwEventPublisher::tearDown() {
  stop();
}


/* TODO: Is this needed, maybe should be different..
unsigned long __stdcall WindowsEtwEventPublisher::winEventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
  UNREFERENCED_PARAMETER(pContext);

  switch (action) {
  case EvtSubscribeActionError:
    VLOG(1) << "Windows event callback failed: " << hEvent;
    break;
  case EvtSubscribeActionDeliver: {
    pt::ptree propTree;
    auto s = parseEvent(hEvent, propTree);
    if (s.ok()) {
      auto ec = createEventContext();
      /// We leave the parsing of the properties up to the subscriber
      ec->eventRecord = propTree;
      ec->channel = stringToWstring(propTree.get("Event.System.Channel", ""));
      EventFactory::fire<WindowsEventLogEventPublisher>(ec);
    } else {
      VLOG(1) << "Error rendering Windows event log: " << s.getCode();
    }
  } break;

  default:
    VLOG(1) << "Received unknown action from Windows event log: "
            << GetLastError();
  }
  return ERROR_SUCCESS;
}


Status WindowsEtwEventPublisher::parseEvent(EVT_HANDLE evt,
                                                 pt::ptree& propTree) {
  DWORD buffSize = 0;
  DWORD buffUsed = 0;
  DWORD propCount = 0;
  LPWSTR xml = nullptr;
  Status status;

  if (!EvtRender(nullptr,
                 evt,
                 EvtRenderEventXml,
                 buffSize,
                 xml,
                 &buffUsed,
                 &propCount)) {
    if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
      buffSize = buffUsed;
      xml = static_cast<LPWSTR>(malloc(buffSize));
      if (xml != nullptr) {
        EvtRender(nullptr,
                  evt,
                  EvtRenderEventXml,
                  buffSize,
                  xml,
                  &buffUsed,
                  &propCount);
      } else {
        status = Status(1, "Unable to reserve memory for event log buffer");
      }
    }
  }

  if (ERROR_SUCCESS == GetLastError()) {
    std::stringstream ss;
    ss << wstringToString(xml);
    read_xml(ss, propTree);
  } else {
    status = Status(GetLastError(), "Event rendering failed");
  }

  if (xml != nullptr) {
    free(xml);
  }

  return status;
} */

bool WindowsEtwEventPublisher::shouldFire(
    const WindowsEtwSubscriptionContextRef& sc,
    const WindowsEtwEventContextRef& ec) const {

  return sc->sources.find(ec->channel) != sc->sources.end();

}

bool WindowsEtwEventPublisher::isSubscriptionActive() const {
  return etw_handles_.size() > 0;
}
}

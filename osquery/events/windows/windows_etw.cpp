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
#define INITGUID

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

// TODO: Assess if these are needed
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/tokenizer.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_etw.h"

namespace pt = boost::property_tree;

namespace osquery {

REGISTER(WindowsEtwEventPublisher, "event_publisher", "windows_etw");

// TODO: Unsure if this is needed
const std::chrono::milliseconds kWinEventLogPause(200);

const std::wstring kOsqueryEtwSessionName = L"osquery etw trace session";

// GUID that identifies your trace session.
// Remember to create your own session GUID.

// {22377e0a-63b0-4f43-a824-4b3554ac8985}
static const GUID kOsquerySessionGuid =
{ 0x22377e0a, 0x63b0, 0x4f43, { 0xa8, 0x24, 0x4b, 0x35, 0x54, 0xac, 0x89, 0x85 } };

// GUID that identifies the provider that you want
// to enable to your session.

// {55404E71 - 4DB9 - 4DEB - A5F5 - 8F86E46DDE56}
static const GUID kProcEventsGuid =
{ 0x55404e71, 0x4db9, 0x4deb, {0xa5, 0xf5, 0x8f, 0x86, 0xe4, 0x6d, 0xde, 0x56 } };

void WindowsEtwEventPublisher::configure() {

  stop();

  ULONG status = ERROR_SUCCESS;
  TRACEHANDLE SessionHandle = 0;
  EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
  ULONG BufferSize = 0;
  BOOL TraceOn = TRUE;

  BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH + sizeof(kOsqueryEtwSessionName);
  pSessionProperties = (EVENT_TRACE_PROPERTIES*) malloc(BufferSize);

  ZeroMemory(pSessionProperties, BufferSize);
  pSessionProperties->Wnode.BufferSize = BufferSize;
  pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
  pSessionProperties->Wnode.Guid = kProcEventsGuid;
  pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
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

void WINAPI processEvent(PEVENT_RECORD pEvent) {

  // Skip as this is the event header
  if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
    pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
    return;
  }

  // Get the size of the buffers first
  unsigned long buffSize = 0;
  PTRACE_EVENT_INFO pInfo = nullptr;
  auto status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &buffSize);

  if (ERROR_INSUFFICIENT_BUFFER == status) {
    pInfo = (TRACE_EVENT_INFO*)malloc(buffSize);
    if (pInfo == nullptr) {
      LOG(WARNING) << "Failed to allocate memory for event info";
      return;
    }

    // Retrieve the event metadata.
    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &buffSize);
  }

  std::stringstream ss;
  ss << std::hex;
  ss << pInfo->EventGuid.Data1 << pInfo->EventGuid.Data2 << pInfo->EventGuid.Data3 << pInfo->EventGuid.Data4;
  VLOG(1) << "Processing event for GUID: " << ss.str();
  VLOG(1) << "number of props: " << pInfo->PropertyCount;
  VLOG(1) << "Event Message:\n\n" << (wchar_t*)(pInfo + pInfo->EventMessageOffset)).c_str());
}

Status WindowsEtwEventPublisher::run() {
  pause();

  ULONG status = ERROR_SUCCESS;
  EVENT_TRACE_LOGFILE trace;
  TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

  ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
  trace.LogFileName = nullptr;
  trace.LoggerName = (LPSTR)kOsqueryEtwSessionName.c_str();
  trace.EventCallback = (PEVENT_CALLBACK)(processEvent);
  trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD |
                           PROCESS_TRACE_MODE_REAL_TIME;

  auto hTrace = OpenTrace(&trace);

  if ((TRACEHANDLE)INVALID_HANDLE_VALUE == hTrace) {
    LOG(WARNING) << "Failed to open the trace for processing with " << GetLastError();
    return Status(1, "Failed to open the trace for processing");
  }

  status = ProcessTrace(&hTrace, 1, 0, 0);

  if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
    LOG(WARNING) << "Failed to process trace with " << status;
    return Status(1, "Failed to process trace");
  }

  if ((TRACEHANDLE)INVALID_HANDLE_VALUE != hTrace) {
    status = CloseTrace(hTrace);
  }

  // TODO: I believe the ETW query should happen here, followed by a fire
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


bool WindowsEtwEventPublisher::shouldFire(
    const WindowsEtwSubscriptionContextRef& sc,
    const WindowsEtwEventContextRef& ec) const {

  // TODO: Fix this up as neede
  // return sc->sources.find(ec->channel) != sc->sources.end();
  return true;

}

bool WindowsEtwEventPublisher::isSubscriptionActive() const {
  return etw_handles_.size() > 0;
}
}

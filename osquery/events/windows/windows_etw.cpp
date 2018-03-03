/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// TODO: Assess if these are needed
//#include <boost/property_tree/json_parser.hpp>
//#include <boost/property_tree/xml_parser.hpp>
//#include <boost/tokenizer.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_etw.h"
#include "osquery/filesystem/fileops.h"

// namespace pt = boost::property_tree;

namespace osquery {

REGISTER(WindowsEtwEventPublisher, "event_publisher", "windows_etw");

const std::string kOsqueryEtwSessionName = "osquery etw trace session";

// GUID that identifies your trace session.
// Remember to create your own session GUID.
// {22377e0a-63b0-4f43-a824-4b3554ac8985}
// TODO: We should probably randomly generate a GUID here.
static const GUID kOsquerySessionGuid = {
    0x22377e0a,
    0x63b0,
    0x4f43,
    {0xa8, 0x24, 0x4b, 0x35, 0x54, 0xac, 0x89, 0x85}};

// MS Kernel Registry events - TODO Look into this
// {70EB4F03-C1DE-4F73-A051-33D13D5413BD}

/*
static const GUID kRegEventsGuid = {
    0x70EB4F03,
    0xC1DE,
    0x4F73,
    {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}};

*/
void WindowsEtwEventPublisher::configure() {
  stop();

  // Start and enable a trace for each GUID we're provided with
  for (const auto& sub : subscriptions_) {
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE SessionHandle = 0;
    EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
    BOOL TraceOn = TRUE;

    unsigned long BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH +
                 sizeof(kOsqueryEtwSessionName);
    pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);

    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;

    auto sc = getSubscriptionContext(sub->context);
    pSessionProperties->Wnode.Guid = sc->guid;
    pSessionProperties->LogFileMode =
        EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
    pSessionProperties->MaximumFileSize = 1; // 1 MB
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pSessionProperties->LogFileNameOffset =
        sizeof(EVENT_TRACE_PROPERTIES) +
        static_cast<unsigned long>(kOsqueryEtwSessionName.size());

    status = StartTrace((PTRACEHANDLE)&SessionHandle,
                        (LPCSTR)kOsqueryEtwSessionName.c_str(),
                        pSessionProperties);

    // If the trace already exists, stop it and restart
    if (status == ERROR_ALREADY_EXISTS) {
      // Pushback a stub GUID for stopping
      etw_handles_.push_back(std::make_pair(sc->guid, 0));
      stop();
      status = StartTrace((PTRACEHANDLE)&SessionHandle,
        (LPCSTR)kOsqueryEtwSessionName.c_str(),
        pSessionProperties);
    }

    if (SessionHandle == 0) {
      LOG(WARNING) << "Failed to start trace for provider with " << status;
      return;
    }

    etw_handles_.push_back(std::make_pair(sc->guid, SessionHandle));

    status = EnableTraceEx2(SessionHandle,
                            (LPCGUID)&sc->guid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION,
                            0,
                            0,
                            0,
                            NULL);
    if (pSessionProperties != nullptr) {
      free(pSessionProperties);
    }
  }
}

// TODO: This needs some heavy cleanup
BOOL WINAPI WindowsEtwEventPublisher::processEtwRecord(PEVENT_RECORD pEvent) {

  // Skip as this is the event header
  if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
      pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
    return FALSE;
  }

  // Get the size of the buffers first
  unsigned long buffSize = 0;
  PTRACE_EVENT_INFO pInfo = nullptr;
  auto status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &buffSize);

  if (ERROR_INSUFFICIENT_BUFFER == status) {
    pInfo = (TRACE_EVENT_INFO*)malloc(buffSize);
    if (pInfo == nullptr) {
      LOG(WARNING) << "Failed to allocate memory for event info";
      return FALSE;
    }

    // Retrieve the event metadata.
    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &buffSize);
  }

  PEVENT_MAP_INFO pMapInfo = nullptr;
  unsigned long mapSize = 0;
  unsigned long formattedDataSize = 0;
  USHORT UserDataConsumed = 0;
  USHORT PropertyLength = 0;
  LPWSTR pFormattedData = NULL;
  auto pUserData = (PBYTE)pEvent->UserData;
  auto pEndOfUserData = (PBYTE)pEvent->UserData + pEvent->UserDataLength;

  unsigned long ptrSize =
      (EVENT_HEADER_FLAG_32_BIT_HEADER ==
       (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
          ? 4
          : 8;

  // The bummer here, is that we often might want the parent of this process.
  // If cmd.exe calls ping.exe, it spawns a new process, and that's what shows
  // up here, as opposed to the cmd.exe PID :(
  // TODO: Can we derive the process name or the parent pid?
  auto responsiblePid = pEvent->EventHeader.ProcessId;
  std::map<std::string, std::string> connDetails;

  for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++) {
    PropertyLength = pInfo->EventPropertyInfoArray[i].length;

    status = TdhGetEventMapInformation(
        pEvent,
        (PWCHAR)((PBYTE)(pInfo) +
                 pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
        pMapInfo,
        &mapSize);

    status = TdhFormatProperty(
        pInfo,
        pMapInfo,
        ptrSize,
        pInfo->EventPropertyInfoArray[i].nonStructType.InType,
        pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
        PropertyLength,
        (USHORT)(pEndOfUserData - pUserData),
        pUserData,
        &formattedDataSize,
        pFormattedData,
        &UserDataConsumed);

    if (ERROR_INSUFFICIENT_BUFFER == status) {
      if (pFormattedData) {
        free(pFormattedData);
        pFormattedData = NULL;
      }

      pFormattedData = (LPWSTR)malloc(formattedDataSize);
      if (pFormattedData == NULL) {
        LOG(WARNING) << "Failed to malloc";
        return FALSE;
      }

      // Retrieve the formatted data.
      status = TdhFormatProperty(
          pInfo,
          pMapInfo,
          ptrSize,
          pInfo->EventPropertyInfoArray[i].nonStructType.InType,
          pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
          PropertyLength,
          (USHORT)(pEndOfUserData - pUserData),
          pUserData,
          &formattedDataSize,
          pFormattedData,
          &UserDataConsumed);
    }

    pUserData += UserDataConsumed;

    auto name = wstringToString(
        (PWCHAR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset));
    connDetails[name] = wstringToString(pFormattedData);
  }

  /// We leave the parsing of the properties up to the subscriber
  auto ec = createEventContext();
  ec->eventData = connDetails;
  ec->etwProviderGuid = pEvent->EventHeader.ProviderId;

  ec->pid = pEvent->EventHeader.ProcessId;
  ec->eventId = pEvent->EventHeader.EventDescriptor.Id;
  ec->level = pEvent->EventHeader.EventDescriptor.Level;
  ec->channel = pEvent->EventHeader.EventDescriptor.Channel;
  ec->uptime = pEvent->EventHeader.ProcessorTime;

  FILETIME ft;
  ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;
  ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
  ec->timestamp = filetimeToUnixtime(ft);

  EventFactory::fire<WindowsEtwEventPublisher>(ec);

  if (pInfo != nullptr) {
    free(pInfo);
  }
  if (pFormattedData != nullptr) {
    free(pFormattedData);
  }
  return TRUE;
}

Status WindowsEtwEventPublisher::run() {
  ULONG status = ERROR_SUCCESS;
  EVENT_TRACE_LOGFILE trace;
  TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

  ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
  trace.LogFileName = nullptr;
  trace.LoggerName = (LPSTR)kOsqueryEtwSessionName.c_str();
  trace.EventCallback = (PEVENT_CALLBACK)processEtwRecord;
  trace.ProcessTraceMode =
      PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

  auto hTrace = OpenTrace(&trace);

  if ((TRACEHANDLE)INVALID_HANDLE_VALUE == hTrace) {
    LOG(WARNING) << "Failed to open the trace for processing with "
                 << GetLastError();
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

  return Status(0, "OK");
}

void WindowsEtwEventPublisher::stop() {

  for (auto& etw : etw_handles_) {
    ULONG status = 0;
    unsigned long BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH +
      sizeof(kOsqueryEtwSessionName);
    EVENT_TRACE_PROPERTIES* pSessionProperties =
        (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);

    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Guid = etw.first;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pSessionProperties->LogFileNameOffset =
        sizeof(EVENT_TRACE_PROPERTIES) +
        static_cast<unsigned long>(kOsqueryEtwSessionName.size());

    status = ControlTrace(etw.second,
                          (LPSTR)kOsqueryEtwSessionName.c_str(),
                          pSessionProperties,
                          EVENT_TRACE_CONTROL_STOP);

    if (status != 0 && status != ERROR_MORE_DATA) {
      LOG(WARNING) << "Failed to stop trace with " << status;
    }

    if (pSessionProperties != nullptr) {
      free(pSessionProperties);
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
  // TODO: This will check if the GUID the subscriber has matches the
  // GUID of the fired Event
  return (IsEqualGUID(ec->etwProviderGuid, sc->guid) == TRUE);
}

bool WindowsEtwEventPublisher::isSubscriptionActive() const {
  return etw_handles_.empty();
}
}

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/system.h>

#include "osquery/core/windows/wmi.h"
#include "osquery/events/windows/windows_etw.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {

REGISTER(WindowsEtwEventPublisher, "event_publisher", "windows_etw");

const std::string kOsqueryEtwSessionName = "osquery-etw-trace";

static const GUID kOsquerySessionGuid = {
    0x22377e0a,
    0x63b0,
    0x4f43,
    {0xa8, 0x24, 0x4b, 0x35, 0x54, 0xac, 0x89, 0x85}};

void WindowsEtwEventPublisher::configure() {
  stop();

  // Start and enable a trace for each GUID we're provided with
  unsigned long buffSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH +
                           sizeof(kOsqueryEtwSessionName);

  auto sessionProperties =
      static_cast<EVENT_TRACE_PROPERTIES*>(malloc(buffSize));

  ZeroMemory(sessionProperties, buffSize);
  sessionProperties->Wnode.BufferSize = buffSize;
  sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  sessionProperties->Wnode.ClientContext = 1;
  sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  sessionProperties->MaximumFileSize = 1;
  sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
  sessionProperties->LogFileNameOffset =
      sizeof(EVENT_TRACE_PROPERTIES) +
      static_cast<unsigned long>(kOsqueryEtwSessionName.size());

  for (const auto& sub : subscriptions_) {
    auto sc = getSubscriptionContext(sub->context);
    sessionProperties->Wnode.Guid = sc->guid;

    PTRACEHANDLE sessionHandle;
    auto session_name = kOsqueryEtwSessionName +
                        "-" + 
                        std::to_string(sc->guid.Data1) + "-" + std::to_string(rand());
    auto status = StartTrace(sessionHandle, (LPCSTR)session_name.c_str(),
                             sessionProperties);

    // If the trace already exists, stop it and restart
    if (status == ERROR_ALREADY_EXISTS) {
      // Pushback a stub GUID for stopping
      etw_handles_.push_back(std::make_pair(sc->guid, nullptr));

      stop();

      status = StartTrace((PTRACEHANDLE)&sessionHandle,
                          (LPCSTR)kOsqueryEtwSessionName.c_str(),
                          sessionProperties);
    }

    if (sessionHandle == 0) {
      LOG(WARNING) << "Failed to start trace for provider with " << status;
      return;
    }

    etw_handles_.push_back(std::make_pair(sc->guid, sessionHandle));

    status = EnableTraceEx2(*sessionHandle,
                            (LPCGUID)&sc->guid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION,
                            0,
                            0,
                            0,
                            nullptr);
  }

  if (sessionProperties != nullptr) {
    free(sessionProperties);
  }
}

bool WINAPI WindowsEtwEventPublisher::processEtwRecord(PEVENT_RECORD pEvent) {
  // Event Header requires no processing
  if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
      pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
    return false;
  }

  unsigned long buffSize = 0;
  PTRACE_EVENT_INFO info = nullptr;
  auto status = TdhGetEventInformation(pEvent, 0, nullptr, info, &buffSize);

  if (ERROR_INSUFFICIENT_BUFFER == status) {
    info = static_cast<TRACE_EVENT_INFO*>(malloc(buffSize));
    if (info == nullptr) {
      LOG(WARNING) << "Failed to allocate memory for event info";
      return false;
    }

    // Retrieve the event metadata.
    status = TdhGetEventInformation(pEvent, 0, nullptr, info, &buffSize);
  }

  std::vector<wchar_t> formattedData;
  auto pUserData = static_cast<PBYTE>(pEvent->UserData);
  auto pEndOfUserData =
      static_cast<PBYTE>(pEvent->UserData) + pEvent->UserDataLength;

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
  unsigned long formattedDataSize = 0;
  unsigned short userDataConsumed = 0;
  unsigned short propLen = 0;
  PEVENT_MAP_INFO mapInfo = nullptr;
  unsigned long mapSize = 0;

  for (unsigned short i = 0; i < info->TopLevelPropertyCount; i++) {
    propLen = info->EventPropertyInfoArray[i].length;

    status = TdhGetEventMapInformation(
        pEvent,
        (wchar_t*)((PBYTE)(info) +
                   info->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
        mapInfo,
        &mapSize);

    status = TdhFormatProperty(
        info,
        mapInfo,
        ptrSize,
        info->EventPropertyInfoArray[i].nonStructType.InType,
        info->EventPropertyInfoArray[i].nonStructType.OutType,
        propLen,
        static_cast<unsigned short>(pEndOfUserData - pUserData),
        pUserData,
        &formattedDataSize,
        formattedData.data(),
        &userDataConsumed);

    if (ERROR_INSUFFICIENT_BUFFER == status) {
      formattedData.resize(formattedDataSize);
      status = TdhFormatProperty(
          info,
          mapInfo,
          ptrSize,
          info->EventPropertyInfoArray[i].nonStructType.InType,
          info->EventPropertyInfoArray[i].nonStructType.OutType,
          propLen,
          static_cast<unsigned short>(pEndOfUserData - pUserData),
          pUserData,
          &formattedDataSize,
          formattedData.data(),
          &userDataConsumed);
    }

    pUserData += userDataConsumed;

    auto name = wstringToString(
        (wchar_t*)((PBYTE)(info) + info->EventPropertyInfoArray[i].NameOffset));
    connDetails[name] = wstringToString(formattedData.data());
  }

  // We leave the parsing of the properties up to the subscriber
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

  if (info != nullptr) {
    free(info);
  }
  return true;
}

Status WindowsEtwEventPublisher::run() {
  EVENT_TRACE_LOGFILE trace;
  ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
  trace.LogFileName = nullptr;
  trace.LoggerName = (LPSTR)kOsqueryEtwSessionName.c_str();
  trace.EventCallback = (PEVENT_CALLBACK)processEtwRecord;
  trace.ProcessTraceMode =
      PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

  auto hTrace = OpenTrace(&trace);
  if (INVALID_PROCESSTRACE_HANDLE == hTrace) {
    return Status(1,
                  "Failed to open the trace for processing with " +
                      std::to_string(GetLastError()));
  }

  // Process the trace in realtime indefinitely
  auto status = ProcessTrace(&hTrace, 1, 0, 0);
  if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
    return Status(1, "Failed to process trace with " + std::to_string(status));
  }

  return Status(0, "OK");
}

void WindowsEtwEventPublisher::stop() {
  unsigned long buffSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH +
                           sizeof(kOsqueryEtwSessionName);

  auto sessionProperties =
      static_cast<EVENT_TRACE_PROPERTIES*>(malloc(buffSize));
  for (auto& etw : etw_handles_) {
    ZeroMemory(sessionProperties, buffSize);
    sessionProperties->Wnode.BufferSize = buffSize;
    sessionProperties->Wnode.Guid = etw.first;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    sessionProperties->LogFileNameOffset =
        sizeof(EVENT_TRACE_PROPERTIES) +
        static_cast<unsigned long>(kOsqueryEtwSessionName.size());

    auto status = ControlTrace(*etw.second,
                               (LPSTR)kOsqueryEtwSessionName.c_str(),
                               sessionProperties,
                               EVENT_TRACE_CONTROL_STOP);

    if (status != 0 && status != ERROR_MORE_DATA) {
      LOG(WARNING) << "Failed to stop trace with " << status;
    }
  }

  if (sessionProperties != nullptr) {
    free(sessionProperties);
  }
  etw_handles_.clear();
}

void WindowsEtwEventPublisher::tearDown() {
  stop();
}

bool WindowsEtwEventPublisher::shouldFire(
    const WindowsEtwSubscriptionContextRef& sc,
    const WindowsEtwEventContextRef& ec) const {
  return (IsEqualGUID(ec->etwProviderGuid, sc->guid) == TRUE);
}

bool WindowsEtwEventPublisher::isSubscriptionActive() const {
  return etw_handles_.empty();
}
} // namespace osquery

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <Windows.h>
#include <winevt.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

namespace osquery {
namespace tables {

const int kNumEventsBlock = 1024;

void parseQueryResults(EVT_HANDLE& queryResults, QueryData& results) {
  // Parse the results
  // EVT_HANDLE hEvents[1024];
  std::vector<EVT_HANDLE> events(kNumEventsBlock);
  unsigned long numEvents = 0;

  // Retrieve the Event logs one block at a time until there's no events returned
  auto ret = EvtNext(
      queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);

  while (ret != FALSE) {

    for (unsigned long i = 0; i < numEvents; i++) {
      // Do a think with the event...
      std::vector<char> renderedContent;
      unsigned long renderedBuffSize = 0;
      unsigned long renderedBuffUsed = 0;
      unsigned long propCount = 0;
      ret = EvtRender(nullptr,
                      events[i],
                      EvtRenderEventXml,
                      renderedBuffSize,
                      renderedContent.data(),
                      &renderedBuffUsed,
                      &propCount);

      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        renderedBuffSize = renderedBuffUsed;
        renderedContent.resize(renderedBuffSize);
        ret = EvtRender(nullptr,
                        events[i],
                        EvtRenderEventXml,
                        renderedBuffSize,
                        renderedContent.data(),
                        &renderedBuffUsed,
                        &propCount);
      }
      if (GetLastError() != ERROR_SUCCESS) {
        LOG(WARNING) << "Failed to render windows event with "
                     << GetLastError();
        continue;
      }

      Row r;

      
      r["data"] = wstringToString(
          std::wstring(renderedContent.begin(), renderedContent.end()).c_str());


      results.push_back(r);

      EvtClose(events[i]);
    }

    ret = EvtNext(
        queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);
  }
}

QueryData genWindowsEventLog(QueryContext& context) {
  QueryData results;

  // TODO: Get the channel from the user
  if (!context.hasConstraint("channel", EQUALS)) {
    LOG(WARNING) << "must specify the event log channel to search";
    return {};
  }

  auto channels = context.constraints["channel"].getAll(EQUALS);

  // TODO Get all other constraints given by the user
  std::wstring searchQuery = L"*";
  // context.hasConstraint("key", EQUALS)

  for (const auto& channel : channels) {
    auto queryResults =
        EvtQuery(nullptr,
                 stringToWstring(channel).c_str(),
                 searchQuery.c_str(),
                 EvtQueryChannelPath | EvtQueryReverseDirection);
    if (queryResults == nullptr) {
      LOG(WARNING) << "Failed to search event log for query with "
                   << GetLastError();
      return {};
    }
    parseQueryResults(queryResults, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery

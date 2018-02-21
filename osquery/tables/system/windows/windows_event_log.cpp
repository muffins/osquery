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

#include <rapidxml.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/windows/wmi.h"

// TODO: Clean this shit up.
using namespace rapidxml;

namespace osquery {
namespace tables {

const int kNumEventsBlock = 1024;

void parseWelXml(std::string& xml, Row& r) {
  xml_document<char> doc;
  doc.parse<0>(&xml[0]);

  auto root = doc.first_node("Event");
  // First parse the system details
  xml_node<>* system = root->first_node("System");

  r["eventid"] = system->first_node("EventID")->value();
  r["task"] = system->first_node("Task")->value();
  r["source"] = system->first_node("Channel")->value();
  r["level"] = system->first_node("Level")->value();
  r["keywords"] = system->first_node("Keywords")->value();
  r["provider_name"] =
      system->first_node("Provider")->first_attribute("Name") == nullptr
          ? ""
          : system->first_node("Provider")->first_attribute("Name")->value();
  r["provider_guid"] =
      system->first_node("Provider")->first_attribute("Guid") == nullptr
          ? ""
          : system->first_node("Provider")->first_attribute("Guid")->value();

  // Next parse the event data fields
  /*
  std::map<std::string, std::string> data;
  auto eventData = root->first_node("EventData");
  for (xml_node<>* node = eventData->first_node("Data"); node;
       node = node->next_sibling()) {
    data[node->first_attribute("Name")->value()] = node->value();
  }
  // TODO: get data
  */
}

void parseQueryResults(EVT_HANDLE& queryResults, QueryData& results) {
  // Parse the results
  std::vector<EVT_HANDLE> events(kNumEventsBlock);
  unsigned long numEvents = 0;

  // Retrieve the events one block at a time
  auto ret = EvtNext(
      queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);

  while (ret != FALSE) {
    for (unsigned long i = 0; i < numEvents; i++) {
      std::vector<wchar_t> renderedContent;
      unsigned long renderedBuffSize = 0;
      unsigned long renderedBuffUsed = 0;
      unsigned long propCount = 0;
      EvtRender(nullptr,
                events[i],
                EvtRenderEventXml,
                renderedBuffSize,
                renderedContent.data(),
                &renderedBuffUsed,
                &propCount);

      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        renderedBuffSize = renderedBuffUsed;
        renderedContent.resize(renderedBuffSize);
        EvtRender(nullptr,
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
      auto xml = wstringToString(renderedContent.data());
      parseWelXml(xml, r);

      results.push_back(r);

      EvtClose(events[i]);
    }

    ret = EvtNext(
        queryResults, kNumEventsBlock, events.data(), INFINITE, 0, &numEvents);
  }
}

QueryData genWindowsEventLog(QueryContext& context) {
  QueryData results;

  if (!context.hasConstraint("source", EQUALS)) {
    LOG(WARNING) << "must specify the event log source to search";
    return {};
  }

  auto channels = context.constraints["source"].getAll(EQUALS);

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

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

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/filesystem/fileops.h"

namespace rx = rapidxml;

namespace osquery {
namespace tables {

const std::string kEventLogXmlPrefix = "<QueryList><Query Id=\"0\">";
const std::string kEventLogXmlSuffix = "</Query></QueryList>";

const int kNumEventsBlock = 1024;

void parseWelXml(std::string& xml, Row& r) {
  rx::xml_document<char> doc;
  doc.parse<0>(&xml[0]);

  auto root = doc.first_node("Event");
  // First parse the system details
  rx::xml_node<>* system = root->first_node("System");

  // All event records should have an EventID
  r["eventid"] = system->first_node("EventID") != nullptr
                     ? system->first_node("EventID")->value()
                     : "-1";

  std::string sysTime{""};
  if (system->first_node("TimeCreated") != nullptr &&
      system->first_node("TimeCreated")->first_attribute("SystemTime") !=
          nullptr) {
    sysTime = system->first_node("TimeCreated")
                  ->first_attribute("SystemTime")
                  ->value();
  }
  r["time"] = sysTime.empty() ? "-1" : sysTime;

  r["task"] = system->first_node("Task") != nullptr
                  ? system->first_node("Task")->value()
                  : "-1";
  r["source"] = system->first_node("Channel") != nullptr
                    ? system->first_node("Channel")->value()
                    : "-1";
  r["level"] = system->first_node("Level") != nullptr
                   ? system->first_node("Level")->value()
                   : "-1";

  unsigned long long keywords = 0;
  if (system->first_node("Keywords") != nullptr) {
    safeStrtoull(system->first_node("Keywords")->value(), 10, keywords);
  }
  r["keywords"] = BIGINT(keywords);

  if (system->first_node("Provider") != nullptr) {
    r["provider_name"] =
        system->first_node("Provider")->first_attribute("Name") == nullptr
            ? ""
            : system->first_node("Provider")->first_attribute("Name")->value();
    r["provider_guid"] =
        system->first_node("Provider")->first_attribute("Guid") == nullptr
            ? ""
            : system->first_node("Provider")->first_attribute("Guid")->value();
  } else {
    r["provider_name"] = "-1";
    r["provider_guid"] = "-1";
  }

  if (system->first_node("Execution") != nullptr) {
    r["pid"] =
        system->first_node("Execution")->first_attribute("ProcessID") == nullptr
            ? ""
            : system->first_node("Execution")
                  ->first_attribute("ProcessID")
                  ->value();
    r["tid"] =
        system->first_node("Execution")->first_attribute("ThreadID") == nullptr
            ? ""
            : system->first_node("Execution")
                  ->first_attribute("ThreadID")
                  ->value();
  } else {
    r["pid"] = "-1";
    r["tid"] = "-1";
  }

  // Next parse the event data fields
  JSON document;
  // auto eventData = root->first_node("EventData");
  unsigned int paramCnt = 0;

  for (auto eventData = system->next_sibling(); eventData;
       eventData = eventData->next_sibling()) {
    JSON evtDataBlock;

    for (auto node = eventData->first_node(); node;
         node = node->next_sibling()) {
      if (node->first_attribute("Name") == nullptr) {
        // Append a counter as Windows event data can contain multiple <Data>
        // elements
        evtDataBlock.add("Data" + std::to_string(paramCnt), node->value());
        paramCnt++;
      } else {
        evtDataBlock.add(node->first_attribute("Name")->value(), node->value());
      }
    }

    document.push(evtDataBlock.getArray());
  }

  std::string data{""};
  document.toString(data);
  r["data"] = data;
}

void parseQueryResults(EVT_HANDLE queryResults, QueryData& results) {
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
  auto eids = context.constraints["eventid"].getAll(EQUALS);

  std::string eidList =
      eids.empty()
          ? "*"
          : "*[System[(EventID=" + osquery::join(eids, " or EventID =") + ")]]";
  std::string welSearchQuery = kEventLogXmlPrefix;
  for (const auto& channel : channels) {
    welSearchQuery += "<Select Path=\"" + channel + "\">";
    welSearchQuery += eidList;
    welSearchQuery += "</Select>" + kEventLogXmlSuffix;

    auto queryResults =
        EvtQuery(nullptr,
                 stringToWstring(channel).c_str(),
                 stringToWstring(welSearchQuery).c_str(),
                 EvtQueryChannelPath | EvtQueryReverseDirection);

    if (queryResults == nullptr) {
      LOG(WARNING) << "Failed to search event log for query with "
                   << GetLastError();
      return {};
    }
    parseQueryResults(queryResults, results);
    EvtClose(queryResults);
  }

  return results;
}
} // namespace tables
} // namespace osquery

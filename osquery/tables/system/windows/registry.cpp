/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// TODO: Remember to remove this :P
#include <iostream>

#include <stdlib.h>

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <iterator>
#include <map>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/core/process.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tables/system/system_utils.h"
#include "osquery/tables/system/windows/registry.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::map<std::string, HKEY> kRegistryHives = {
    {"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT},
    {"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG},
    {"HKEY_CURRENT_USER", HKEY_CURRENT_USER},
    {"HKEY_CURRENT_USER_LOCAL_SETTINGS", HKEY_CURRENT_USER_LOCAL_SETTINGS},
    {"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE},
    {"HKEY_PERFORMANCE_DATA", HKEY_PERFORMANCE_DATA},
    {"HKEY_PERFORMANCE_NLSTEXT", HKEY_PERFORMANCE_NLSTEXT},
    {"HKEY_PERFORMANCE_TEXT", HKEY_PERFORMANCE_TEXT},
    {"HKEY_USERS", HKEY_USERS},
};

const std::map<unsigned long, std::string> kRegistryTypes = {
    {REG_BINARY, "REG_BINARY"},
    {REG_DWORD, "REG_DWORD"},
    {REG_DWORD_BIG_ENDIAN, "REG_DWORD_BIG_ENDIAN"},
    {REG_EXPAND_SZ, "REG_EXPAND_SZ"},
    {REG_LINK, "REG_LINK"},
    {REG_MULTI_SZ, "REG_MULTI_SZ"},
    {REG_NONE, "REG_NONE"},
    {REG_QWORD, "REG_QWORD"},
    {REG_SZ, "REG_SZ"},
    {REG_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR"},
    {REG_RESOURCE_LIST, "REG_RESOURCE_LIST"},
};

/// Microsoft helper function for getting the contents of a registry key
void queryKey(const std::string& hive,
              const std::string& key,
              QueryData& results) {
  if (kRegistryHives.count(hive) != 1) {
    return;
  }

  HKEY hRegistryHandle;
  auto retCode = RegOpenKeyEx(kRegistryHives.at(hive),
                              TEXT(key.c_str()),
                              0,
                              KEY_READ,
                              &hRegistryHandle);

  if (retCode != ERROR_SUCCESS) {
    return;
  }

  const unsigned long maxKeyLength = 255;
  const unsigned long maxValueName = 16383;
  std::vector<char> achClass(MAX_PATH);
  unsigned long cchClassName = MAX_PATH;
  unsigned long cSubKeys = 0;
  unsigned long cbMaxSubKey;
  unsigned long cchMaxClass;
  unsigned long cValues;
  unsigned long cchMaxValueName;
  unsigned long cbMaxValueData;
  unsigned long cbSecurityDescriptor;
  FILETIME ftLastWriteTime;
  retCode = RegQueryInfoKey(hRegistryHandle,
                            achClass.data(),
                            &cchClassName,
                            nullptr,
                            &cSubKeys,
                            &cbMaxSubKey,
                            &cchMaxClass,
                            &cValues,
                            &cchMaxValueName,
                            &cbMaxValueData,
                            &cbSecurityDescriptor,
                            &ftLastWriteTime);

  if (retCode != ERROR_SUCCESS) {
    return;
  }

  std::vector<char> achKey(maxKeyLength);
  unsigned long cbName;

  // Process registry subkeys
  if (cSubKeys > 0) {
    for (unsigned long i = 0; i < cSubKeys; i++) {
      cbName = maxKeyLength;
      retCode = RegEnumKeyEx(hRegistryHandle,
                             i,
                             achKey.data(),
                             &cbName,
                             nullptr,
                             nullptr,
                             nullptr,
                             &ftLastWriteTime);
      if (retCode != ERROR_SUCCESS) {
        continue;
      }
      Row r;
      fs::path keyPath(key);
      r["hive"] = hive;
      r["key"] = keyPath.string();
      r["subkey"] = (keyPath / achKey).string();
      r["name"] = "(Default)";
      r["type"] = "REG_SZ";
      r["data"] = "(value not set)";
      r["mtime"] = std::to_string(osquery::filetimeToUnixtime(ftLastWriteTime));
      results.push_back(r);
    }
  }

  if (cValues <= 0) {
    return;
  }

  auto bpDataBuff = new unsigned char[cbMaxValueData];
  auto cchValue = maxKeyLength;
  char achValue[maxValueName];

  // Process registry values
  for (unsigned long i = 0; i < cValues; i++) {
    ZeroMemory(bpDataBuff, cbMaxValueData);
    cchValue = maxValueName;
    achValue[0] = '\0';
    retCode = RegEnumValue(hRegistryHandle,
                           i,
                           achValue,
                           &cchValue,
                           nullptr,
                           nullptr,
                           nullptr,
                           nullptr);

    if (retCode != ERROR_SUCCESS) {
      continue;
    }

    auto lpData = cbMaxValueData;
    unsigned long lpType;
    retCode = RegQueryValueEx(
        hRegistryHandle, achValue, nullptr, &lpType, bpDataBuff, &lpData);

    if (retCode != ERROR_SUCCESS) {
      continue;
    }

    Row r;
    fs::path keyPath(key);
    r["hive"] = hive;
    r["key"] = keyPath.string();
    r["subkey"] = keyPath.string();
    r["name"] = achValue;
    if (kRegistryTypes.count(lpType) > 0) {
      r["type"] = kRegistryTypes.at(lpType);
    } else {
      r["type"] = "UNKNOWN";
    }
    r["mtime"] = std::to_string(osquery::filetimeToUnixtime(ftLastWriteTime));

    bpDataBuff[cbMaxValueData - 1] = 0x00;

    /// REG_LINK is a Unicode string, which in Windows is wchar_t
    char* regLinkStr = nullptr;
    if (lpType == REG_LINK) {
      regLinkStr = new char[cbMaxValueData];
      const size_t newSize = cbMaxValueData;
      size_t convertedChars = 0;
      wcstombs_s(&convertedChars,
                 regLinkStr,
                 newSize,
                 reinterpret_cast<wchar_t*>(bpDataBuff),
                 _TRUNCATE);
    }

    auto bpDataBuffTmp = bpDataBuff;
    std::vector<std::string> multiSzStrs;
    std::vector<char> regBinary;
    std::string data;

    switch (lpType) {
    case REG_FULL_RESOURCE_DESCRIPTOR:
    case REG_RESOURCE_LIST:
    case REG_BINARY:
      for (size_t j = 0; j < cbMaxValueData; j++) {
        regBinary.push_back(static_cast<char>(bpDataBuff[j]));
      }
      boost::algorithm::hex(
          regBinary.begin(), regBinary.end(), std::back_inserter(data));
      r["data"] = data;
      break;
    case REG_DWORD:
      r["data"] = std::to_string(*reinterpret_cast<int*>(bpDataBuff));
      break;
    case REG_DWORD_BIG_ENDIAN:
      r["data"] =
          std::to_string(_byteswap_ulong(*reinterpret_cast<int*>(bpDataBuff)));
      break;
    case REG_EXPAND_SZ:
      r["data"] = std::string(reinterpret_cast<char*>(bpDataBuff));
      break;
    case REG_LINK:
      r["data"] = std::string(regLinkStr);
      break;
    case REG_MULTI_SZ:
      while (*bpDataBuffTmp != 0x00) {
        std::string s(reinterpret_cast<char*>(bpDataBuffTmp));
        bpDataBuffTmp += s.size() + 1;
        multiSzStrs.push_back(s);
      }
      r["data"] = boost::algorithm::join(multiSzStrs, ",");
      break;
    case REG_NONE:
      r["data"] = std::string(reinterpret_cast<char*>(bpDataBuff));
      break;
    case REG_QWORD:
      r["data"] =
          std::to_string(*reinterpret_cast<unsigned long long*>(bpDataBuff));
      break;
    case REG_SZ:
      r["data"] = std::string(reinterpret_cast<char*>(bpDataBuff));
      break;
    default:
      r["data"] = "";
      break;
    }
    results.push_back(r);
    if (regLinkStr != nullptr) {
      delete[](regLinkStr);
    }
  }
  delete[](bpDataBuff);
  RegCloseKey(hRegistryHandle);
};

QueryData genRegistry(QueryContext& context) {
  QueryData results;
  std::set<std::string> rHives;
  std::set<std::string> rKeys;
  std::set<std::string> rUsers;

  /// By default, we display all HIVEs
  if (context.constraints["hive"].exists(EQUALS) &&
      context.constraints["hive"].getAll(EQUALS).size() > 0) {
    rHives = context.constraints["hive"].getAll(EQUALS);
  } else {
    for (auto& h : kRegistryHives) {
      rHives.insert(h.first);
    }
  }

  /// By default, we display all keys in each HIVE
  if (context.constraints["key"].exists(EQUALS) &&
      context.constraints["key"].getAll(EQUALS).size() > 0) {
    rKeys = context.constraints["key"].getAll(EQUALS);
  } else {
    rKeys.insert("");
  }

  /// By default, we display all keys in each HIVE
  if (context.constraints["uid"].exists(EQUALS) &&
      context.constraints["uid"].getAll(EQUALS).size() > 0) {
    rUsers = context.constraints["uid"].getAll(EQUALS);
  } else {
    /// If the user doesn't specify a context (sid), we specify the current user.
    rUsers.insert(std::to_string(platformGetUid()));
  }

  auto contextUsers = usersFromContext(context);

  for (auto& hive : rHives) {
    for (auto& key : rKeys) {
      // TODO: Let's consider warning users leveraging 'HKCU' that this is
      // TODO: querying against the current executing users SID
      if (hive.find("CURRENT_USER") != std::string::npos) {
        /// We map the current_user HIVE to the HKEY_USERS hive using the SID
        auto userHive = std::string("HKEY_USERS");
        for (const auto& user : contextUsers) {
          auto userKey = user.at("uuid") + std::string("\\") + key;
          queryKey(userHive, userKey, results);
        }
      } else {
        queryKey(hive, key, results);
      }
    }
  }

  return results;
}
}
}

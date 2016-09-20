/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <initguid.h>
#include <mstask.h>
#include <msterr.h>
#include <ole2.h>
#include <wchar.h>
#include <windows.h>

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

ULONG kNumberTasksToRetreive = 5;

QueryData genScheduledTasks(QueryContext& context) {
  QueryData results;

  HRESULT hr = S_OK;
  ITaskScheduler* pITS;

  hr = CoInitialize(nullptr);
  if (FAILED(hr)) {
    return results;
  }

  hr = CoCreateInstance(CLSID_CTaskScheduler,
                        nullptr,
                        CLSCTX_INPROC_SERVER,
                        IID_ITaskScheduler,
                        (void**)&pITS);

  if (FAILED(hr)) {
    CoUninitialize();
    return results;
  }

  IEnumWorkItems* pIEnum;
  hr = pITS->Enum(&pIEnum);
  pITS->Release();
  if (FAILED(hr)) {
    CoUninitialize();
    return results;
  }

  LPWSTR* lpwszNames;
  DWORD dwFetchedTasks = 0;
  while (SUCCEEDED(pIEnum->Next(
             kNumberTasksToRetreive, &lpwszNames, &dwFetchedTasks)) &&
         (dwFetchedTasks != 0)) {
    while (dwFetchedTasks) {
      std::cout << lpwszNames[--dwFetchedTasks] << std::endl;
      CoTaskMemFree(lpwszNames[dwFetchedTasks]);
    }
    CoTaskMemFree(lpwszNames);
  }

  pIEnum->Release();
  CoUninitialize();

  return results;
}
}
}

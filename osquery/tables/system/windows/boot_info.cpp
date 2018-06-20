/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

// NOTE: This needs to be included last to avoid redefinition of windows symbols
#include <tbs.h>

namespace osquery {
namespace tables {

QueryData genBootInfo(QueryContext& context) {

  UINT32 tcg_log_size = 0;
  // Get the buffsize of the TCG Log
  Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, 0, &tcg_log_size);

  std::vector<BYTE> tcg_log(0x0, tcg_log_size);
  Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, tcg_log.data(), &tcg_log_size);

  

  return {};
}
} // namespace tables
} // namespace osquery
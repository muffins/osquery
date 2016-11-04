
#include "osquery/acquisition/acquisition.h"

namespace fs = boost::filesystem;

namespace osquery {

Status Acquisition::makeAcquisitionDir() {
  if (!fs::path::exists(kAcquisitionStore)) {
    fs::create_directory(kAcquisitionStore);
  }
  return fs::path::exists(kAcquisitionStore) ? Status.ok() : Status.fail();
}

Status Acquisition::carveFile(fs::path p) {
  Status s;
  s = makeAcquisitionDir();
  if (!s.ok()) {
    TLOG << "Unable to create acquisition directory";
  }

  ifstream source(p, ios::binary);
  ofstream dest(kAcquisitionStore, ios::binary);

  dest << source.rdbuf();

  source.close();
  dest.close();

  return Status.ok();
}

Status Acquisition::Status carveMemory() {
  return Status.ok();
}
}

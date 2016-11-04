
#include <boost/filesystem/path.hpp>

#include <osquery/logger.h>

namespace fs = boost::filesystem;

namespace osquery {

class Acquisition {
 private
  /**
   * @brief create the osquery acquisition directory
   *
   * This function ensures our temp store for carved files/mem exists
   */
  Status makeAcquisitionDir();

  const fs::path kOsqueryAcquisitionStore = "/tmp/osquery-acq";

 public
  /**
   * @brief default constructor
   *
   */
  Acquisition(){};
  /**
   * @brief default destructor
   *
   */
  ~Acquisition(){};

  /**
   * @brief carves a specified file from the disk and stores it in the store
   *
   * Given a path to a file, this function will carve the file residing at
   * the path and store the result in the temp directory
   */
  Status carveFile(fs::path p);

  /**
   * @brief carves a specified file from the disk and stores it in the store
   *
   * Given a path to a file, this function will carve the file residing at
   * the path and store the result in the temp directory
   */
  Status carveMemory();
}
}

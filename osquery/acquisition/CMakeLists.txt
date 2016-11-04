ADD_OSQUERY_LIBRARY(TRUE osquery_acquisition
  acquisition.cpp
)

ADD_OSQUERY_LIBRARY(FALSE osquery_acquisition_plugins
  plugins/tls.cpp
)

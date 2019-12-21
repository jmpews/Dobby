include_directories(.)

set(logging.SOURCE_FILE_LIST
  ./cxxlogging.cc
  ./logging.c
)

set(logging.SOURCE_HEADER_LIST
  ./logging/logging.h
  ./logging/check_logging.h
  ./logging/cxxlogging.h
)

if(BUILD_INDEPENDENT_LIBRARY)
add_library(logging STATIC
  ${logging.SOURCE_FILE_LIST}
  ${logging.SOURCE_HEADER_LIST}
)
endif()
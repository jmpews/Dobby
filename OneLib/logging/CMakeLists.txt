include_directories(.)

set(SOURCE_FILE_LIST
  ./cxxlogging.cc
  ./logging.c
)

set(SOURCE_HEADER_LIST
  logging/logging.h
  logging/check_logging.h
  logging/cxxlogging.h
)

add_library(logging STATIC
  ${SOURCE_FILE_LIST}
  ${SOURCE_HEADER_LIST}
)
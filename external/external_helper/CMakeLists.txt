include_directories(.)

set(SOURCE_FILE_LIST
  variable_cache.c
  async_logger.cc
)

set(SOURCE_HEADER_LIST
  async_logger.cc
  variable_cache.h
)

add_library(external_helper STATIC
  ${SOURCE_FILE_LIST}
  ${SOURCE_HEADER_LIST}
)
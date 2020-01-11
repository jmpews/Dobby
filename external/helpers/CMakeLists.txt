include_directories(.)

set(SOURCE_FILE_LIST
  ./variable_cache.c
)

set(SOURCE_HEADER_LIST
  ./variable_cache.h
)

add_library(helpers STATIC
  ${SOURCE_FILE_LIST}
  ${SOURCE_HEADER_LIST}
)
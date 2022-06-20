if(SYSTEM.Darwin)
set(SOURCE_FILE_LIST
  ${CMAKE_CURRENT_SOURCE_DIR}/dobby_import_replace.cc
  )
endif()

add_library(global_offset_table_hook INTERFACE
  ${SOURCE_FILE_LIST}
  )

include_directories(
  .
)

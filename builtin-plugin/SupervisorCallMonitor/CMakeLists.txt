add_library(supervisior_call_monitor SHARED
  async_logger.cc
  MachUtility.cc
  loader.cc
  system_call.cc
  mach_system_call.cc
)

include_directories(
  .
)

target_link_libraries(supervisior_call_monitor
  ${dobby_output_name}
  )
add_executable(apple_silicon_example
  main.cc
  darwin_common_api.cc
)

target_link_libraries(apple_silicon_example
  Dobby
)
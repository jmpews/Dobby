set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(socket_example
  main.cc
  socket_example.cc
  )

target_link_libraries(socket_example
  dobby Threads::Threads
  )


add_library(socket_example_lib SHARED
  socket_example.cc
  )

target_link_libraries(socket_example_lib
  dobby Threads::Threads
  )

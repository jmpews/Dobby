if(SYSTEM.Darwin)
  add_executable(darwin-example
    main.cc
    darwin_common_api.cc
  )

  target_link_libraries(darwin-example
    DobbyX
  )
endif()

if(SYSTEM.Android)
  add_executable(android-example
    main.cc
    android_common_api.cc
    )

  target_link_libraries(android-example
    dobby
    )
endif()
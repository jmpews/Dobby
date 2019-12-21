cmake_minimum_required(VERSION 3.5)
project(RuntimeSupport)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")


set(RuntimeSupport.SOURCE_FILE
    FunctionInlineReplaceExport.cc
    TrampolineStubRebase.cc
)

include_directories(
    .
    ${Target.path}
)

if(SYSTEM.iOS)
    # -lstdc++
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -stdlib=libc++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()
add_library(RuntimeSupport SHARED
    ${RuntimeSupport.SOURCE_FILE}
)

if (MSVC)
    # Used for the 'and', 'or' ... keywords - See: http://www.cplusplus.com/reference/ciso646/
    set_property(TARGET RuntimeSupport PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

set_property(TARGET RuntimeSupport PROPERTY CXX_STANDARD           11)
set_property(TARGET RuntimeSupport PROPERTY CXX_STANDARD_REQUIRED  ON)

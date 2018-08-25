set(CMAKE_LEGACY_CYGWIN_WIN32 0)
cmake_minimum_required(VERSION 2.8)

project(saitama_assembly_core)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -arch arm64")
message(STATUS "C_FLAGS: ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")
message(STATUS "CXX_FLAGS: ${CMAKE_CXX_FLAGS}")

option(X_LOG "enable dbug log" ON)
option(X_SHARED "build shared library" ON)

if(X_LOG)
    ADD_DEFINITIONS(-DX_LOG=1)
else()
    ADD_DEFINITIONS(-DX_LOG=0)
endif()

set(GLOBAL.SOURCE_FILE)
set(GLOBAL.SOURCE_DIR)
set(GLOBAL.HEADER_FILE)
set(GLOBAL.HEADER_DIR)

set(Project.path .)
set(Target.path ./src)

set(Target.SOURCE_DIR
)

set(Target.arch arm64)
set(Target.SOURCE_FILE
  ${Target.path}/arch/${Target.arch}/assembler-${Target.arch}.cc
)

set(Target.HEADER_FILE
  ${Target.path}/arch/${Target.arch}/assembler-${Target.arch}.h
  ${Target.path}/arch/${Target.arch}/codegen-${Target.arch}.h
  ${Target.path}/arch/${Target.arch}/constants-${Target.arch}.h
  ${Target.path}/arch/${Target.arch}/instructions-${Target.arch}.h
  ${Target.path}/arch/${Target.arch}/registers-${Target.arch}.h
  ${Target.path}/arch/${Target.arch}/stub-code-${Target.arch}.h
)

set(Target.HEADER_FILE ${Target.HEADER_FILE}
  ${Target.path}/base/objects/objects.h
  ${Target.path}/base/objects/code.h
  ${Target.path}/base/heap.h
  ${Target.path}/base/code-buffer.h
)

# utils
set(Target.HEADER_FILE ${Target.HEADER_FILE}
  ${Target.path}/utils.h
)

set(Target.SOURCE_FILE ${Target.SOURCE_FILE}
  ${Target.path}/platform/posix/platform-posix.cc
)

include_directories(
  ${Project.path}
  ${Target.path}
)

if(X_SHARED)
    # build shared library
    add_library(saitama_assembly_core SHARED ${Target.HEADER_FILE} ${Target.SOURCE_FILE})
else()
    # build static library
    add_library(saitama_assembly_core STATIC ${Target.HEADER_FILE} ${Target.SOURCE_FILE})
endif()

add_executable(test_it test/test-arm64.cc)
target_link_libraries(test_it saitama_assembly_core)
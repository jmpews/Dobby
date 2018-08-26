cmake_minimum_required(VERSION 3.5)
project(HookZz)

include(cmake/Util.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
enable_language(ASM)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

option(CXX "use cxx source" ON)
option(USE_POSIX_IN_DARWIN "use posix function in darwin" OFF)
option(X_LOG "enable debug log" ON)
option(X_SHARED "build shared library" ON)


if(PLATFORM STREQUAL "iOS")
    set(SYSTEM.iOS 1)
elseif(PLATFORM STREQUAL "Android")
    set(SYSTEM.Android 1)
else()
    message(FATAL_ERROR "[!] ONLY SUPPORT [iOS|Android] X_PLATFORM")
endif()

if(ARCH STREQUAL "arm" OR ARCH STREQUAL "armv7")
    set(CMAKE_SYSTEM_PROCESSOR arm)
    set(PROCESSOR.arm 1)
elseif(ARCH STREQUAL "aarch64" OR ARCH STREQUAL "arm64" OR ARCH STREQUAL "armv8")
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
    set(PROCESSOR.aarch64 1)
else()
    message(FATAL_ERROR "[!] ONLY SUPPORT [[arm|armv7]|[aarch64|arm64|armv8]] ARCH")
endif()

include(cmake/Macros.cmake)

set(Target.path .)
set(Target.arch arm64)
set(Target.cpp_prefix ARM64)
set(Target.cc_suffix arm64)
set(Target.SOURCE_FILE
#  ${Target.path}/srcxx/arch/${Target.arch}/${Target.cpp_prefix}InstructionRelocation.cpp
#  ${Target.path}/srcxx/arch/${Target.arch}/closure-bridge-template-${Target.cc_suffix}.c
#  ${Target.path}/srcxx/arch/${Target.arch}/closure-trampoline-template-${Target.cc_suffix}.S
#  ${Target.path}/srcxx/arch/${Target.arch}/dynamic-closure-trampoline-template-${Target.cc_suffix}.S
)


if(CXX)

set(Target.SOURCE_DIR
        ${Target.path}
        ${Target.path}/srcxx
        )
set(Target.SOURCE_DIR ${Target.SOURCE_DIR}
        ${Target.path}/srcxx/base_core
        ${Target.path}/srcxx/base_core/objects
        ${Target.path}/srcxx/base_core/platform
        ${Target.path}/srcxx/base_core/platform/platform-posix
        )
set(Target.SOURCE_DIR ${Target.SOURCE_DIR}
        ${Target.path}/srcxx/assembly_core
        )
if(PROCESSOR.aarch64)
    set(Target.SOURCE_DIR ${Target.SOURCE_DIR}
        ${Target.path}/srcxx/assembly_core/arch/arm64
        ${Target.path}/srcxx/assembly_core/modules/assembler
        )
    set(Target.SOURCE_DIR ${Target.SOURCE_DIR}
        ${Target.path}/srcxx/arch/arm64
        )
endif()
# *.cc
search_suffix_files("cc" Target.SOURCE_DIR Target.SOURCE_CC)

# *.cpp
search_suffix_files("cpp" Target.SOURCE_DIR Target.SOURCE_CPP)

# *.c
search_suffix_files("c" Target.SOURCE_DIR Target.SOURCE_C)

# *.S
search_suffix_files("S" Target.SOURCE_DIR Target.SOURCE_ASSEMBLY)

# *.h
search_suffix_files("h" Target.SOURCE_DIR Target.HEADER_H)

set(Target.SOURCE_FILE ${Target.SOURCE_FILE} ${Target.SOURCE_CC} ${Target.SOURCE_CPP} ${Target.SOURCE_C} ${Target.SOURCE_ASSEMBLY})
set(Target.HEADER_FILE ${Target.HEADER_FILE} ${Target.HEADER_H} include/hookzz.h)

message(STATUS "Target.HEADER_FILE = ${Target.HEADER_FILE}")

else()
endif()

include_directories(${Target.HEADER_DIR} ${Target.SOURCE_DIR})

message(STATUS "Target.SOURCE_FILE ${Target.SOURCE_DIR}")

if(SHARED)
    # build shared library
    add_library(hookzz SHARED ${Target.SOURCE_FILE} ${Target.HEADER_FILE})
else()
    # build static library
    add_library(hookzz STATIC ${Target.SOURCE_FILE} ${Target.HEADER_FILE})
endif()

target_include_directories(hookzz PUBLIC ./include)

if(CMAKE_SYSTEM_NAME MATCHES "^Android")
    target_link_libraries(hookzz log)
endif()
# macOS build iOS
## arm64
#>>> cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/ios.toolchain.cmake -DIOS_PLATFORM=OS -DIOS_ARCH=arm64 -DENABLE_ARC=FALSE -DZPLATFORM=iOS -DZARCH=arm64
#>>> make
## armv7
#>>> cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/ios.toolchain.cmake -DIOS_PLATFORM=OS -DIOS_ARCH=armv7 -DENABLE_ARC=FALSE -DZPLATFORM=iOS -DZARCH=armv7
#>>> make

cmake_minimum_required(VERSION 3.5)
project(HookZz)

include(cmake/ios.toolchain.cmake)
include(cmake/Util.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
enable_language(ASM)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

set(CMAKE_ASM_FLAGS "-arch arm64 -fembed-bitcode")

option(CXX OFF "use cxx source")
option(USE_POSIX_IN_DARWIN OFF "use posix function in darwin")
option(X_LOG ON "enable debug log")
option(X_SHARED ON "build shared library")

if(X_LOG)
    ADD_DEFINITIONS(-DX_LOG=1)
else()
    ADD_DEFINITIONS(-DX_LOG=0)
endif()

if(X_BACKEND STREQUAL "Darwin")
    set(SYSTEM.Darwin 1)
elseif(X_BACKEND STREQUAL "Linux")
    set(SYSTEM.Linux 1)
endif()

if(X_PLATFORM STREQUAL "iOS")
    set(SYSTEM.iOS 1)
elseif(PLATFORM STREQUAL "Android")
    set(SYSTEM.Android 1)
else()
    message(FATAL_ERROR "[!] ONLY SUPPORT [iOS|Android] PLATFORM")
endif()

if(X_ARCH STREQUAL "arm" OR X_ARCH STREQUAL "armv7")
    set(CMAKE_SYSTEM_PROCESSOR arm)
    set(PROCESSOR.arm 1)
elseif(X_ARCH STREQUAL "aarch64" OR X_ARCH STREQUAL "arm64" OR X_ARCH STREQUAL "armv8")
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
    set(PROCESSOR.aarch64 1)
else()
    message(FATAL_ERROR "[!] ONLY SUPPORT [[arm|armv7]|[aarch64|arm64|armv8]] ARCH")
endif()

include(cmake/Macros.cmake)

set(GLOBAL.SOURCE_FILE)
set(GLOBAL.SOURCE_DIR)
set(GLOBAL.HEADER_FILE)
set(GLOBAL.HEADER_DIR)

if(CXX)
else()
    # build c source
    set(HookZz.Path .)
    set(GLOBAL.SOURCE_DIR
            ${HookZz.Path}/src
            ${HookZz.Path}/src/std_kit
            ${HookZz.Path}/src/thread_support
            ${HookZz.Path}/src/compiler-rt/lib/builtins
            )

    set(GLOBAL.HEADER_DIR
            ${HookZz.Path}/include
            )
    
    if(SYSTEM.Android)
        set(GLOBAL.SOURCE_DIR ${GLOBAL.SOURCE_DIR}
            ${HookZz.Path}/src/platforms/backend-posix
            ${HookZz.Path}/src/platforms/backend-linux
            )
        add_definitions(-DDYNAMIC_CLOSURE_BRIDGE=0)
    elseif(SYSTEM.Darwin)
        set(GLOBAL.SOURCE_DIR ${GLOBAL.SOURCE_DIR}
            ${HookZz.Path}/src/platforms/backend-posix
            ${HookZz.Path}/src/platforms/backend-darwin
            )
        add_definitions(-DDYNAMIC_CLOSURE_BRIDGE=1)
        if(USE_POSIX_IN_DARWIN)
            add_definitions(-DUSE_POSIX_IN_DARWIN=1)
        else()
            add_definitions(-DUSE_POSIX_IN_DARWIN=0)
        endif()
    endif()
    if(PROCESSOR.aarch64)
        set(GLOBAL.SOURCE_DIR ${GLOBAL.SOURCE_DIR}
            ${HookZz.Path}/src/platforms/arch-arm64
            )
    endif()

    # *.c
    search_suffix_files("c" GLOBAL.SOURCE_DIR HookZz.SOURCE_C)

    # *.S
    search_suffix_files("S" GLOBAL.SOURCE_DIR HookZz.SOURCE_ASSEMBLY)

    # *.h
    search_suffix_files("h" GLOBAL.SOURCE_DIR HookZz.HEADER_H)

    set(GLOBAL.SOURCE_FILE ${GLOBAL.SOURCE_FILE} ${HookZz.SOURCE_C} ${HookZz.SOURCE_ASSEMBLY})
    set(GLOBAL.HEADER_FILE ${GLOBAL.HEADER_FILE} ${HookZz.HEADER_H})
endif()

include_directories(${GLOBAL.HEADER_DIR} ${GLOBAL.SOURCE_DIR})

if(X_SHARED)
    # build shared library
    add_library(hookzz SHARED ${GLOBAL.SOURCE_FILE} ${GLOBAL.HEADER_FILE})
else()
    # build static library
    add_library(hookzz STATIC ${GLOBAL.SOURCE_FILE} ${GLOBAL.HEADER_FILE})
endif()

target_include_directories(hookzz PUBLIC ./include)
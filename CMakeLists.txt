cmake_minimum_required(VERSION 3.5)
project(HookZz)

include(cmake/Util.cmake)
include(cmake/Globals.cmake)
include(cmake/Macros.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
enable_language(ASM)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -stdlib=libc++ -fvisibility=hidden")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")
SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")
SET(CMAKE_ASM_FLAGS "${CFLAGS}  -x assembler-with-cpp")

option(SHARED "Build shared library" ON)
option(DEBUG "Enable debug log" ON)
option(CLOSURE_BRIDGE_TEMPLATE "Enable closure bridge assembly template" OFF)

if(CLOSURE_BRIDGE_TEMPLATE)
    add_definitions(-DENABLE_CLOSURE_BRIDGE_TEMPLATE)
endif()

if(DEBUG)
   add_definitions(-DDEBUG)
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

#set(SYSTEM.Windows 1)
#set(PROCESSOR.X86_64 1)

# Platform
if(PLATFORM STREQUAL "iOS")
    set(SYSTEM.iOS 1)
    MESSAGE(STATUS "[*] Compile for iOS")
elseif(PLATFORM STREQUAL "Android")
    set(SYSTEM.Android 1)
    MESSAGE(STATUS "[*] Compile for Android")
elseif(SYSTEM.Windows)
    MESSAGE(STATUS "[*] Compile for Windows")
else()
    if(SYSTEM.Android OR SYSTEM.Linux)
        set(SYSTEM.Android 1)
    elseif(SYSTEM.Darwin)
        set(SYSTEM.iOS 1)
    else()
        message(FATAL_ERROR "[!] ONLY SUPPORT [iOS|Android] PLATFORM")
    endif()
endif()

if(SYSTEM.iOS)
    # -lstdc++
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -stdlib=libc++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
elseif(SYSTEM.Android)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s -Wl,--gc-sections")
endif()

# Architecture
if(ARCH STREQUAL "arm" OR ARCH STREQUAL "armv7")
    set(CMAKE_SYSTEM_PROCESSOR arm)
    set(PROCESSOR.arm 1)
    MESSAGE(STATUS "[*] Compile for arm")
elseif(ARCH STREQUAL "aarch64" OR ARCH STREQUAL "arm64" OR ARCH STREQUAL "armv8")
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
    set(PROCESSOR.aarch64 1)
    MESSAGE(STATUS "[*] Compile for aarch64")
elseif(PROCESSOR.X86_64)
    MESSAGE(STATUS "[*] Compile for X86_64")
else()
    if(PROCESSOR.arm)
        set(CMAKE_SYSTEM_PROCESSOR arm)
        MESSAGE(STATUS "[*] Compile for arm")
    elseif(PROCESSOR.aarch64)
        set(CMAKE_SYSTEM_PROCESSOR aarch64)
        MESSAGE(STATUS "[*] Compile for aarch64")
    else()
        message(FATAL_ERROR "[!] ONLY SUPPORT [[arm|armv7]|[aarch64|arm64|armv8]] ARCH")
    endif()
endif()

if(PROCESSOR.arm)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch armv7")
elseif(PROCESSOR.aarch64)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64")
elseif(PROCESSOR.X86_64)
endif()

set(Target.path .)

set(Target.SOURCE_DIR
    ${Target.path}/OneLib
    ${Target.path}/OneLib/include
    ${Target.path}/OneLib/stdcxx
    ${Target.path}/OneLib/logging
    ${Target.path}/srcxx
    ${Target.path}/srcxx/MultiThreadSupport
    ${Target.path}/srcxx/ExecMemory
    ${Target.path}/srcxx/UserMode
    ${Target.path}/srcxx/core
    ${Target.path}/srcxx/core/arch
    ${Target.path}/srcxx/core/modules
    ${Target.path}/srcxx/ExtraInternalPlugin
)

set(Target.SOURCE_DIR ${Target.SOURCE_DIR}
    ${Target.path}/srcxx/ClosureTrampolineBridge/arm64
    ${Target.path}/srcxx/InstructionRelocation/arm64
    ${Target.path}/srcxx/core/arch/arm64
    ${Target.path}/srcxx/InterceptRouting/arm64
    ${Target.path}/srcxx/UserMode/arm64
    ${Target.path}/srcxx/ExtraInternalPlugin/ARM64
    ${Target.path}/srcxx/PlatformInterface/platform-posix
    ${Target.path}/srcxx/PlatformInterface/platform-darwin
)

set(Target.SOURCE_FILE
    ${Target.path}/srcxx/PlatformInterface/platform-posix.cc
    ${Target.path}/srcxx/PlatformInterface/platform-darwin.cc

    ${Target.path}/srcxx/core/modules/assembler/assembler.cc
    ${Target.path}/srcxx/core/modules/assembler/assembler-arm64.cc

    ${Target.path}/srcxx/core/modules/codegen/codegen-arm64.cc

    ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionWrapper/function-wrapper-arm64.cc
    ${Target.path}/srcxx/InterceptRoutingPlugin/FunctionInlineReplace/function-inline-replace-arm64.cc
    ${Target.path}/srcxx/InterceptRoutingPlugin/DynamicBinaryInstrument/dynamic-binary-instrument-arm64.cc
)

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



set(Target.SOURCE_FILE ${Target.SOURCE_FILE}
    ${ASSEMBLER.SOURCE_FILE}
    ${CODEGEN.SOURCE_FILE}
)

set(Target.HEADER_FILE ${Target.HEADER_FILE}
    ${ASSEMBLER.HEADER_FILE}
    ${CODEGEN.HEADER_FILE}
)


include_directories(${Target.HEADER_DIR} ${Target.SOURCE_DIR})

if(SHARED)
    # build shared library
    add_library(hookzz SHARED ${Target.SOURCE_FILE} ${Target.HEADER_FILE} include/hookzz.h)
else()
    # build static library
    add_library(hookzz STATIC ${Target.SOURCE_FILE} ${Target.HEADER_FILE} include/hookzz.h)
endif()

target_include_directories(hookzz PUBLIC ./include)

if(CMAKE_SYSTEM_NAME MATCHES "^Android")
    target_link_libraries(hookzz log)
endif()

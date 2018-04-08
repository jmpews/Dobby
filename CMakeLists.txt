message(FATAL_ERROR "just dummy CMakeLists.txt")

cmake_minimum_required(VERSION 3.8)
project(HookZz)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET ${triple})
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_COMPILER_TARGET ${triple})

set(CMAKE_C_FLAGS "-O0 -g")
set(CMAKE_CXX_FLAGS "-stdlib=libc++ -std=c++11 -gmodules")

include_directories(
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_SOURCE_DIR}/src"
)


aux_source_directory(src HOOKZZ_SRC)
aux_source_directory(src/platforms/arch-arm HOOKZZ_ARCH_ARM_SRC)
aux_source_directory(src/platforms/backend-arm HOOKZZ_BACKEND_ARM_SRC)
aux_source_directory(src/platforms/backend-posix HOOKZZ_BACKEND_POSIX_SRC)

aux_source_directory(src/zzdeps ZZDEPS_SRC)
aux_source_directory(src/zzdeps/darwin ZZDEPS_DARWIN_SRC)
aux_source_directory(src/zzdeps/posix ZZDEPS_POSIX_SRC)
aux_source_directory(src/zzdeps/common ZZDEPS_COMMON_SRC)

set(FINAL_SRC
        ${HOOKZZ_SRC}
        ${HOOKZZ_ARCH_ARM_SRC}
        ${HOOKZZ_BACKEND_ARM_SRC}
        ${HOOKZZ_BACKEND_POSIX_SRC}
        ${ZZDEPS_SRC}
        ${ZZDEPS_DARWIN_SRC}
        ${ZZDEPS_POSIX_SRC}
        ${ZZDEPS_COMMON_SRC}
        )

# xcode-cross-compile

# CMAKE_ZZ_DARWIN_PLATFORM: [ios, macos]
# CMAKE_ZZ_DARWIN_ARCH: [arm, arm64, x86_64, x86]
# CMAKE_ZZ_DARWIN_XCODE_PLATFORM: <iphoneos, macosx>
# CMAKE_ZZ_DARWIN_XCODE_ARCH: <armv7, armv7s, x86_64, x86>
# CMAKE_DARWIN_SYSROOT: 

# Get the Xcode version being used.
execute_process(COMMAND xcodebuild -version
        OUTPUT_VARIABLE XCODE_VERSION
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "Xcode [0-9\\.]+" XCODE_VERSION "${XCODE_VERSION}")
string(REGEX REPLACE "Xcode ([0-9\\.]+)" "\\1" XCODE_VERSION "${XCODE_VERSION}")
message(STATUS "Building with Xcode version: ${XCODE_VERSION}")

if (NOT CMAKE_ZZ_DARWIN_PLATFORM)
    set(CMAKE_ZZ_DARWIN_PLATFORM "ios")
endif()

set(CMAKE_ZZ_DARWIN_PLATFORM ${CMAKE_ZZ_DARWIN_PLATFORM} CACHE STRING
        "Type of DARWIN platform for which to build.")
if (CMAKE_ZZ_DARWIN_PLATFORM STREQUAL "ios")
    set(CMAKE_ZZ_DARWIN_XCODE_PLATFORM iphoneos)
    set(CMAKE_ZZ_DARWIN_XCODE_ARCH armv7 arm64)
else()
    message(FATAL_ERROR "Invalid CMAKE_ZZ_DARWIN_PLATFORM: ${CMAKE_ZZ_DARWIN_PLATFORM}")
endif()
message(STATUS "Configuring darwin build for platform: ${CMAKE_ZZ_DARWIN_PLATFORM}, "
        "architecture(s): ${CMAKE_ZZ_DARWIN_XCODE_ARCH}")

# If user did not specify the SDK root to use, then query xcodebuild for it.
if (NOT CMAKE_ZZ_DARWIN_SYSROOT)
    execute_process(COMMAND xcodebuild -version -sdk ${CMAKE_ZZ_DARWIN_XCODE_PLATFORM} Path
            OUTPUT_VARIABLE CMAKE_ZZ_DARWIN_SYSROOT
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using SDK: ${CMAKE_ZZ_DARWIN_SYSROOT} for platform: ${CMAKE_ZZ_DARWIN_PLATFORM}")
endif()
if (NOT EXISTS ${CMAKE_ZZ_DARWIN_SYSROOT})
    message(FATAL_ERROR "Invalid CMAKE_ZZ_DARWIN_SYSROOT: ${CMAKE_ZZ_DARWIN_SYSROOT} "
            "does not exist.")
endif()

# Get the SDK version information.
execute_process(COMMAND xcodebuild -sdk ${CMAKE_ZZ_DARWIN_SYSROOT} -version SDKVersion
        OUTPUT_VARIABLE CMAKE_ZZ_DARWIN_SDK_VERSION
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT CMAKE_ZZ_DARWIN_DEVELOPER_ROOT)
    get_filename_component(CMAKE_ZZ_DARWIN_PLATFORM_SDK_DIR ${CMAKE_ZZ_DARWIN_SYSROOT} PATH)
    get_filename_component(CMAKE_ZZ_DARWIN_DEVELOPER_ROOT ${CMAKE_ZZ_DARWIN_PLATFORM_SDK_DIR} PATH)
endif()
if (NOT EXISTS ${CMAKE_ZZ_DARWIN_DEVELOPER_ROOT})
    message(FATAL_ERROR "Invalid CMAKE_ZZ_DARWIN_DEVELOPER_ROOT: "
            "${CMAKE_ZZ_DARWIN_DEVELOPER_ROOT} does not exist.")
endif()

# Find the C & C++ compilers for the specified SDK.
if (NOT CMAKE_C_COMPILER)
    execute_process(COMMAND xcrun -sdk ${CMAKE_ZZ_DARWIN_SYSROOT} -find clang
            OUTPUT_VARIABLE CMAKE_C_COMPILER
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using C compiler: ${CMAKE_C_COMPILER}")
endif()
if (NOT CMAKE_CXX_COMPILER)
    execute_process(COMMAND xcrun -sdk ${CMAKE_ZZ_DARWIN_SYSROOT} -find clang++
            OUTPUT_VARIABLE CMAKE_CXX_COMPILER
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Using CXX compiler: ${CMAKE_CXX_COMPILER}")
endif()

# Get the version of Darwin (OS X) of the host.
execute_process(COMMAND uname -r
        OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_VERSION
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)

# Standard settings.
set(CMAKE_SYSTEM_NAME Darwin CACHE INTERNAL "")
set(CMAKE_SYSTEM_VERSION ${IOS_SDK_VERSION} CACHE INTERNAL "")
set(UNIX TRUE CACHE BOOL "")
set(APPLE TRUE CACHE BOOL "")
set(IOS TRUE CACHE BOOL "")
set(CMAKE_AR ar CACHE FILEPATH "" FORCE)
set(CMAKE_RANLIB ranlib CACHE FILEPATH "" FORCE)

# Skip the platform compiler checks for cross compiling.
set(CMAKE_CXX_COMPILER_FORCED TRUE)
set(CMAKE_CXX_COMPILER_WORKS TRUE)
set(CMAKE_C_COMPILER_FORCED TRUE)
set(CMAKE_C_COMPILER_WORKS TRUE)

# All iOS/Darwin specific settings - some may be redundant.
set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dylib")
set(CMAKE_SHARED_MODULE_PREFIX "lib")
set(CMAKE_SHARED_MODULE_SUFFIX ".so")
set(CMAKE_MODULE_EXISTS 1)
set(CMAKE_DL_LIBS "")

set(CMAKE_C_FLAGS
        "${XCODE_IOS_PLATFORM_VERSION_FLAGS} ${BITCODE} -fobjc-abi-version=2 -fobjc-arc ${CMAKE_C_FLAGS}")
# Hidden visibilty is required for C++ on iOS.
set(CMAKE_CXX_FLAGS
        "${XCODE_IOS_PLATFORM_VERSION_FLAGS} ${BITCODE} -fvisibility=hidden -fvisibility-inlines-hidden -fobjc-abi-version=2 -fobjc-arc ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG -O3 -fomit-frame-pointer -ffast-math ${BITCODE} ${CMAKE_CXX_FLAGS_RELEASE}")
set(CMAKE_C_LINK_FLAGS "${XCODE_IOS_PLATFORM_VERSION_FLAGS} -Wl,-search_paths_first ${CMAKE_C_LINK_FLAGS}")
set(CMAKE_CXX_LINK_FLAGS "${XCODE_IOS_PLATFORM_VERSION_FLAGS}  -Wl,-search_paths_first ${CMAKE_CXX_LINK_FLAGS}")

set(CMAKE_PLATFORM_HAS_INSTALLNAME 1)
set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "-dynamiclib -headerpad_max_install_names")
set(CMAKE_SHARED_MODULE_CREATE_C_FLAGS "-bundle -headerpad_max_install_names")
set(CMAKE_SHARED_MODULE_LOADER_C_FLAG "-Wl,-bundle_loader,")
set(CMAKE_SHARED_MODULE_LOADER_CXX_FLAG "-Wl,-bundle_loader,")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".dylib" ".so" ".a")


add_library(HookZz ${FINAL_SRC})
cmake_minimum_required(VERSION 3.5)
project(HookZz)
set(PrimaryPath ../..)

include(${PrimaryPath}/cmake/Util.cmake)
include(${PrimaryPath}/cmake/Globals.cmake)
include(${PrimaryPath}/cmake/Macros.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

include_directories(third-party/LIEF/include)
SET_OPTION(LIEF_DOC OFF)
SET_OPTION(LIEF_PYTHON_API OFF)
SET_OPTION(LIEF_EXAMPLES OFF)
SET_OPTION(LIEF_ENABLE_JSON OFF)
SET_OPTION(LIEF_LOGGING OFF)
SET_OPTION(LIEF_FROZEN_ENABLED OFF)
SET_OPTION(LIEF_USE_CCACHE OFF)
SET_OPTION(LIEF_OAT OFF)
SET_OPTION(LIEF_DEX OFF)
SET_OPTION(LIEF_VDEX OFF)
SET_OPTION(LIEF_ART OFF)
SET_OPTION(BUILD_SHARED_LIBS OFF)
add_subdirectory(third-party/LIEF)

add_subdirectory(${PrimaryPath} hookzz.out)

add_executable(MachOStaticHook
    main.cc
)

target_link_libraries(MachOStaticHook
    hookzz
    LIB_LIEF
)
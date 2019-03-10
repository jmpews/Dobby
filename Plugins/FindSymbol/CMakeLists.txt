cmake_minimum_required(VERSION 3.5)

set(PrimaryPath ../..)

include(${PrimaryPath}/cmake/Util.cmake)
include(${PrimaryPath}/cmake/Macros.cmake)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")

set(TargetSource )

include_directories(.)

set(TargetSource darwin/find-symbol-darwin.c)

add_library(findsymbol STATIC ${TargetSource})
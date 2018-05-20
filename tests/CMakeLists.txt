cmake_minimum_required(VERSION 2.8)
project(HookZz)

set(CMAKE_CXX_STANDARD 11)
enable_language(ASM)
# set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_FLAGS "-g")

# ======= SaitamaKit =======
set(SaitamaKit.Path ../src/SaitamaKit)

set(SaitamaKit.Source_C_DIR
    ${SaitamaKit.Path}/CommonKit
    ${SaitamaKit.Path}/PosixKit
)

if(ZPLATFORM STREQUAL "Linux")
    set(SaitamaKit.Source_C_DIR
        ${SaitamaKit.Source_C_DIR}
        ${SaitamaKit.Path}/LinuxKit
        ${SaitamaKit.Path}/ELFKit
    )
elseif(ZPLATFORM STREQUAL "Darwin")
    set(SaitamaKit.Source_C_DIR
        ${SaitamaKit.Source_C_DIR}
        ${SaitamaKit.Path}/DarwinKit
        ${SaitamaKit.Path}/MachoKit
    )
else()
    message(FATAL_ERROR "Pease Specify -DZLATFORM = [Linux/Darwin] !!!")
endif()

foreach(file_path ${SaitamaKit.Source_C_DIR})
    file(GLOB_RECURSE file_source_c ${file_path}/*.c)
    set(SaitamaKit.Source_C ${SaitamaKit.Source_C} ${file_source_c})
endforeach()
# message(STATUS ${SaitamaKit.Source_C})

set(GLOBAL_Source_C ${GLOBAL_Source_C} ${SaitamaKit.Source_C})
set(GLOBAL_Source_INCLUDE ${GLOBAL_Source_INCLUDE} ${SaitamaKit.Path} ${SaitamaKit.Path}/include ${SaitamaKit.Source_C_DIR})

# ======= HookZz =======

set(HookZz.Path ../src)

set(HookZz.Source_C_DIR
    ${HookZz.Source_C_DIR}
    ${HookZz.Path}/platforms/arch-arm64
)

foreach(file_path ${HookZz.Source_C_DIR})
    file(GLOB file_source_c ${file_path}/*.c)
    set(HookZz.Source_C ${HookZz.Source_C} ${file_source_c})
endforeach()

set(GLOBAL_Source_C ${GLOBAL_Source_C}
    ${HookZz.Path}/platforms/backend-darwin/memory-darwin.c
    ${HookZz.Path}/debuglog.c
    ${HookZz.Path}/memhelper.c
    ${HookZz.Path}/memory.c
)

set(GLOBAL_Source_INCLUDE ${GLOBAL_Source_INCLUDE}
    ${HookZz.Path}
)

# message(STATUS ${HookZz.Source_C})

set(GLOBAL_Source_C ${GLOBAL_Source_C} ${HookZz.Source_C})
set(GLOBAL_Source_INCLUDE ${GLOBAL_Source_INCLUDE} ${HookZz.Source_C_DIR})

# ======= GLOBAL =======

include_directories(../include ${GLOBAL_Source_INCLUDE})

add_executable(test_arm64_relocator test_arm64_relocator.c ${GLOBAL_Source_C})

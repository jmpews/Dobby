# linux/macOS build Android
#>>> export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle
## arm64
#>>> cmake .. -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_NDK=$ANDROID_NDK -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI=arm64-v8a -DZPLATFORM=Android -DZARCH=arm64
#>>> make
## armv7
#>>> cmake .. -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_NDK=$ANDROID_NDK -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI=armeabi-v7a -DZPLATFORM=Android -DZARCH=armv7
#>>> make

# windows build Android
#>>> set path=%path%;xxx\cmake\3.6.4111459\bin
#>>> set ANDROID_NDK=D:\TechnicalProgramFiles\Android-SDK\ndk-bundle
## arm64
#>>> cmake .. -G "Android Gradle - Ninja" -DCMAKE_TOOLCHAIN_FILE=%ANDROID_NDK%\build\cmake\android.toolchain.cmake -DAN DROID_NDK=%ANDROID_NDK% -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI=arm64-v8a -DZPLATFORM=Android -DZARCH=arm64
#>>> ninja
## armv7
#>>> cmake .. -G "Android Gradle - Ninja" -DCMAKE_TOOLCHAIN_FILE=%ANDROID_NDK%\build\cmake\android.toolchain.cmake -DAN DROID_NDK=%ANDROID_NDK% -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI=armeabi-v7a -DZPLATFORM=Android -DZARCH=armv7
#>>> ninja

# macOS build iOS
## arm64
#>>> cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/ios.toolchain.cmake -DIOS_PLATFORM=OS -DIOS_ARCH=arm64 -DENABLE_ARC=FALSE -DZPLATFORM=iOS -DZARCH=arm64
#>>> make
## armv7
#>>> cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/ios.toolchain.cmake -DIOS_PLATFORM=OS -DIOS_ARCH=armv7 -DENABLE_ARC=FALSE -DZPLATFORM=iOS -DZARCH=armv7
#>>> make

cmake_minimum_required(VERSION 2.8)
project(HookZz)

set(CMAKE_CXX_STANDARD 11)
enable_language(ASM)

set(CMAKE_C_FLAGS "-g -std=gnu11")
# set(CMAKE_VERBOSE_MAKEFILE ON)

if(ZPLATFORM STREQUAL "iOS")
    if(ZARCH STREQUAL "armv7")
        set(CMAKE_ASM_FLAGS "-arch armv7 -fembed-bitcode")
    elseif(ZARCH STREQUAL "arm64")
        set(CMAKE_ASM_FLAGS "-arch arm64 -fembed-bitcode")
    else()
        message(FATAL_ERROR "ZARCH only support [armv7/arm64]!!!")
    endif()
elseif(ZPLATFORM STREQUAL "Android")
else()
    message(FATAL_ERROR "ZPLATFORM only support [iOS/Android]!!!")
endif()

message(STATUS "CMAKE_TOOLCHAIN_FILE='${CMAKE_TOOLCHAIN_FILE}'")

set(GLOBAL_Source_INCLUDE )
set(GLOBAL_Source_C )

# ======= fishhook =======
if(ZPLATFORM STREQUAL "iOS")
    set(fishhook.Path src/deps/fishhook)
    set(fishhook.Source_C_DIR ${fishhook.Path})
    file(GLOB_RECURSE fishhook.Source_C ${fishhook.Source_C_DIR}/*.c)
    set(GLOBAL_Source_C ${GLOBAL_Source_C} ${fishhook.Source_C})
    set(GLOBAL_Source_INCLUDE ${GLOBAL_Source_INCLUDE} ${fishhook.Source_C_DIR})
endif()

# ======= SaitamaKit =======
set(SaitamaKit.Path src/SaitamaKit)

set(SaitamaKit.Source_C_DIR
    ${SaitamaKit.Path}/CommonKit
    ${SaitamaKit.Path}/PosixKit
)

if(ZPLATFORM STREQUAL "Android")
    set(SaitamaKit.Source_C_DIR
        ${SaitamaKit.Source_C_DIR}
        ${SaitamaKit.Path}/LinuxKit
        ${SaitamaKit.Path}/ELFKit
    )
elseif(ZPLATFORM STREQUAL "iOS")
    set(SaitamaKit.Source_C_DIR
        ${SaitamaKit.Source_C_DIR}
        ${SaitamaKit.Path}/DarwinKit
        ${SaitamaKit.Path}/MachoKit
    )
else()
    message(FATAL_ERROR "Pease Specify -DPLATFORM = [Android/iOS] !!!")
endif()

foreach(file_path ${SaitamaKit.Source_C_DIR})
    file(GLOB_RECURSE file_source_c ${file_path}/*.c)
    set(SaitamaKit.Source_C ${SaitamaKit.Source_C} ${file_source_c})
endforeach()
# message(STATUS ${SaitamaKit.Source_C})

set(GLOBAL_Source_C ${GLOBAL_Source_C} ${SaitamaKit.Source_C})
set(GLOBAL_Source_INCLUDE ${GLOBAL_Source_INCLUDE} ${SaitamaKit.Path} ${SaitamaKit.Path}/include ${SaitamaKit.Source_C_DIR})

# ======= HookZz =======

set(HookZz.Path src)

set(HookZz.Source_C_DIR
    ${HookZz.Path}
    ${HookZz.Path}/platforms/backend-posix
)

if(ZPLATFORM STREQUAL "Android")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/platforms/backend-linux
    )
elseif(ZPLATFORM STREQUAL "iOS")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/platforms/backend-darwin
    )
else()
    message(FATAL_ERROR "Pease Specify -DPLATFORM = [Android/iOS] !!!")
endif()

if(ZARCH STREQUAL "armv7")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/platforms/arch-arm
        ${HookZz.Path}/platforms/backend-arm
    )
elseif(ZARCH STREQUAL "arm64")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/platforms/arch-arm64
        ${HookZz.Path}/platforms/backend-arm64
    )
else()
    message(FATAL_ERROR "Pease Specify -DARCH = [armv7/arm64] !!!")
endif()

foreach(file_path ${HookZz.Source_C_DIR})
    file(GLOB file_source_c ${file_path}/*.c)
    set(HookZz.Source_C ${HookZz.Source_C} ${file_source_c})
endforeach()

foreach(file_path ${HookZz.Source_C_DIR})
    file(GLOB file_source_assembly ${file_path}/*.s ${file_path}/*.S)
    set(HookZz.Source_Assembly ${HookZz.Source_Assembly} ${file_source_assembly})
endforeach()
# message(STATUS ${HookZz.Source_C})

set(GLOBAL_Source_C ${GLOBAL_Source_C} ${HookZz.Source_C})
set(GLOBAL_Source_INCLUDE ${GLOBAL_Source_INCLUDE} ${HookZz.Source_C_DIR})

# ======= GLOBAL =======

# Any one option is fine
# set(${CMAKE_ASM_FLAGS} "-arch arm64 -fembed-bitcode")
# set_property(SOURCE ${HookZz.Source_Assembly} PROPERTY LANGUAGE C)
# set_property(SOURCE ${HookZz.Source_Assembly} PROPERTY COMPILE_FLAGS "-arch arm64 -fembed-bitcode")

include_directories(include ${GLOBAL_Source_INCLUDE})
if(BUILD_SHARED)
    add_library(hookzz SHARED ${GLOBAL_Source_C} ${HookZz.Source_Assembly})
else()
    add_library(hookzz STATIC ${GLOBAL_Source_C} ${HookZz.Source_Assembly})
endif()

target_include_directories(hookzz PUBLIC ./include)

if(ZPLATFORM STREQUAL "Android")
    target_link_libraries(hookzz log)
elseif(ZPLATFORM STREQUAL "iOS")
    target_link_libraries(hookzz "-framework Foundation")
endif()

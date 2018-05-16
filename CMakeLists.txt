# cmake -G "Android Gradle - Ninja" -DCMAKE_TOOLCHAIN_FILE="D:\TechnicalProgramFiles\Android-SDK\ndk-bundle\build\cmake\android.toolchain.cmake" .. -DCMAKE_MAKE_PROGRAME="D:\TechnicalProgramFiles\Android-SDK\cmake\3.6.4111459\bin\ninja.exe" -DANDROID_NDK="D:\TechnicalProgramFiles\Android-SDK\ndk-bundle" -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI="arm64-v8a" -DPLATFORM="Android" -DARCH="arm64" 

# cmake -G "MinGW Makefiles" -DCMAKE_TOOLCHAIN_FILE="D:\TechnicalProgramFiles\Android-SDK\ndk-bundle\build\cmake\android.toolchain.cmake" .. -DCMAKE_MAKE_PROGRAME=D:\TechnicalProgramFiles\Android-SDK\ndk-bundle\prebuilt/windows-x86_64/bin/make.exe -DANDROID_NDK="D:\TechnicalProgramFiles\Android-SDK\ndk-bundle" -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI="arm64-v8a" -DPLATFORM="Android" -DARCH="arm64" 
cmake_minimum_required(VERSION 2.8)
project(HookZz)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE ON)

# ======= SaitamaKit =======
set(SaitamaKit.Path src/SaitamaKit)

set(SaitamaKit.Source_C_DIR
    ${SaitamaKit.Path}/CommonKit
    ${SaitamaKit.Path}/PosixKit
)

if(PLATFORM STREQUAL "Android")
    set(SaitamaKit.Source_C_DIR
        ${SaitamaKit.Source_C_DIR}
        ${SaitamaKit.Path}/LinuxKit
        ${SaitamaKit.Path}/ELFKit
    )
elseif(PLATFORM STREQUAL "iOS")
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
message(STATUS ${SaitamaKit.Source_C})

# ======= HookZz =======

set(HookZz.Path src)

set(HookZz.Source_C_DIR
    ${HookZz.Path}
    ${HookZz.Path}/backend-posix
)

if(PLATFORM STREQUAL "Android")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/backend-linux
    )
elseif(PLATFORM STREQUAL "iOS")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/backend-darwin
    )
else()
    message(FATAL_ERROR "Pease Specify -DPLATFORM = [Android/iOS] !!!")
endif()

if(ARCH STREQUAL "armv7")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/arch-arm
        ${HookZz.Path}/backend-arm
    )
elseif(ARCH STREQUAL "arm64")
    set(HookZz.Source_C_DIR
        ${HookZz.Source_C_DIR}
        ${HookZz.Path}/arch-arm64
        ${HookZz.Path}/backend-arm64
    )
else()
    message(FATAL_ERROR "Pease Specify -DARCH = [armv7/arm64] !!!")
endif()

foreach(file_path ${HookZz.Source_C_DIR})
    file(GLOB file_source_c ${file_path}/*.c)
    set(HookZz.Source_C ${HookZz.Source_C} ${file_source_c})
endforeach()
message(STATUS ${HookZz.Source_C})

add_library(hookzz STATIC ${SaitamaKit.Source_C} ${HookZz.Source_C})
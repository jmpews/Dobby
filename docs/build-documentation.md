# Installation

## Clone the project

```
git clone --depth 1 git@github.com:jmpews/Dobby.git
```

## Cmake build options

```
option(DOBBY_GENERATE_SHARED "Build shared library" ON)

option(DOBBY_DEBUG "Enable debug logging" ON)

option(NearBranch "Enable Near Branch Trampoline" ON)

option(DynamicBinaryInstrument "Enable Dynamic Binary Instrument" ON)

option(FullFloatingPointRegisterPack "Save and pack all floating-point registers" OFF)

option(GenerateDarwinFramework "Build darwin framework library" ON)

option(Plugin.SymbolResolver "Resolve symbol by [DobbySymbolResolver] " ON)

option(Plugin.LinkerLoadCallback "Register image load callback " OFF)
```

## Build for host

```
cd Dobby && mkdir build_for_host && cd build_for_host

cmake ..

make -j4
```

## Build for iOS / macOS

#### Manual build for macOS X64 host

```
cd Dobby && mkdir build_for_macos_x64 && cd build_for_macos_x64

cmake .. \
-DCMAKE_BUILD_TYPE=Release \

make -j4
```

#### Manual build for iOS [ARM/ARM64]

```
cd Dobby && mkdir build_for_ios_arm64 && cd build_for_ios_arm64

cmake .. \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DPLATFORM=OS64 -DARCHS="arm64" -DCMAKE_SYSTEM_PROCESSOR=arm64 \
-DENABLE_BITCODE=0 -DENABLE_ARC=0 -DENABLE_VISIBILITY=1 -DDEPLOYMENT_TARGET=9.3

make -j4
```

if you want generate Xcode Project, just replace with `cmake -G Xcode`.

## Build for Android

#### Manual build for Android ARM64

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

cd Dobby && mkdir build_for_android_arm64 && cd build_for_android_arm64

cmake .. \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_ARCH_ABI="arm64-v8a" -DCMAKE_ANDROID_NDK=$ANDROID_NDK -DCMAKE_SYSTEM_VERSION=21 -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang

make -j4
```

#### Manual build for Android ARM

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

cd Dobby && mkdir build_for_android_arm && cd build_for_android_arm

-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_ARCH_ABI="armeabi-v7a" -DCMAKE_ANDROID_NDK=$ANDROID_NDK -DCMAKE_SYSTEM_VERSION=16 -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang 

make -j4
```

#### Android Studio CMake

```
set(DobbyHome D:/TimeDisk/Workspace/Project.wrk/Dobby)
include_directories(
  ${DobbyHome}/include
  ${DobbyHome}/builtin-plugin
  ${DobbyHome}/builtin-plugin/SymbolResolver
  ${DobbyHome}/builtin-plugin/AndroidRestriction
  ${DobbyHome}/external/logging
)

add_library( # Sets the name of the library.
  native-lib
  # Sets the library as a shared library.
  SHARED

  ${DobbyHome}/builtin-plugin/AndroidRestriction/android_restriction_demo.cc

  ${DobbyHome}/builtin-plugin/ApplicationEventMonitor/posix_file_descriptor_operation_monitor.cc
  ${DobbyHome}/builtin-plugin/ApplicationEventMonitor/dynamic_loader_monitor.cc

  # Provides a relative path to your source file(s).
  native-lib.cpp)

macro(SET_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
SET_OPTION(DOBBY_DEBUG ON)
SET_OPTION(DOBBY_GENERATE_SHARED OFF)
SET_OPTION(DynamicBinaryInstrument ON)
SET_OPTION(NearBranch ON)
SET_OPTION(Plugin.SymbolResolver ON)
add_subdirectory(${DobbyHome} dobby)
```
# Installation

## Clone the project

```
git clone --depth 1 git@github.com:jmpews/Dobby.git
```

## Build for host

```
cd Dobby && mkdir build_for_host && cd build_for_host

cmake ..

make -j4
```

## Build for iOS

#### Manual build for iOS[ARM/ARM64]

```
cd Dobby && mkdir build_for_ios_arm64 && cd build_for_ios_arm64

cmake .. \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DPLATFORM=OS64 \
-DARCHS=arm64 \
-DENABLE_BITCODE=1 \
-DENABLE_ARC=0 \
-DENABLE_VISIBILITY=1 \
-DDEPLOYMENT_TARGET=9.3 \
-DCMAKE_SYSTEM_PROCESSOR=aarch64 \
-DDynamicBinaryInstrument=ON -DNearBranchTrampoline=ON \
-DPlugin.FindSymbol=ON -DPlugin.HideLibrary=ON -DPlugin.ObjectiveC=ON

make -j4
```

if you want generate Xcode Project, just replace with `cmake -G Xcode`.

## Build for Android

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

cd Dobby && mkdir build_for_android_arm64 && cd build_for_android_arm64

cmake .. \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_SYSTEM_NAME=Android \
-DCMAKE_ANDROID_ARCH_ABI="arm64-v8a" \
-DCMAKE_ANDROID_NDK=$ANDROID_NDK \
-DCMAKE_SYSTEM_VERSION=21 \
-DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang \
-DDynamicBinaryInstrument=ON

make -j4
```

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

cd Dobby && mkdir build_for_android_arm && cd build_for_android_arm

cmake .. \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_SYSTEM_NAME=Android \
-DCMAKE_ANDROID_ARCH_ABI="armeabi-v7a" \
-DCMAKE_ANDROID_NDK=$ANDROID_NDK \
-DCMAKE_SYSTEM_VERSION=14 \
-DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang \
-DDynamicBinaryInstrument=ON

make -j4
```

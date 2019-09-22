# Installation

## Clone the project

```
git clone --branch dev --depth 1 git@github.com:jmpews/HookZz.git
```

## Build for host

```
cd HookZz && mkdir build_for_host && cd build_for_host && cmake .. && make
```

## Build for iOS

#### Use BuildScript for iOS & Simulator

```
cd BuildScript
sh ./build_64_fat_macho.sh
```

#### Manual build for iOS[ARM/ARM64]

```
cd HookZz && mkdir build_for_ios_arm64 && cd build_for_ios_arm64

cmake .. \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DPLATFORM=OS64 \
-DARCHS=arm64 \
-DENABLE_BITCODE=0 \
-DENABLE_ARC=0 \
-DENABLE_VISIBILITY=0 \
-DDEPLOYMENT_TARGET=9.3 \
-DCMAKE_SYSTEM_PROCESSOR=aarch64 \
-DSHARED=ON \
-DHOOKZZ_DEBUG=OFF

make -j4
```

if you want generate Xcode Project, just replace with `cmake -G Xcode `.


## Build for Android

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

cd HookZz && mkdir build_for_android_arm64 && cd build_for_android_arm64

cmake .. \
-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
-DCMAKE_BUILD_TYPE=Release \
-DANDROID_ABI="arm64-v8a" \
-DANDROID_NATIVE_API_LEVEL=android-21 \
-DSHARED=ON \
-DHOOKZZ_DEBUG=OFF

make -j4
```

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

cd HookZz && mkdir build_for_android_arm && cd build_for_android_arm

cmake .. \
-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
-DCMAKE_BUILD_TYPE=Release \
-DANDROID_ABI="armeabi-v7a" \
-DANDROID_STL=c++_static \
-DANDROID_NATIVE_API_LEVEL=android-14 \
-DSHARED=ON \
-DHOOKZZ_DEBUG=OFF

make -j4
```

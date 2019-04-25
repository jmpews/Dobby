# HookZz    [![](https://img.shields.io/badge/chat-on--discord-7289da.svg?style=flat-square&longCache=true&logo=discord)](https://discord.gg/P4uCTTH)

A hook framework for arm / arm64(aarch64) / x86_64 / iOS / Android / Linux / Windows

_tips: any question [go to Discord](https://discordapp.com/invite/P4uCTTH)_


## 1. Build & Compile

#### 1.0 Clone the project

```
git clone --branch dev --depth 1 git@github.com:jmpews/HookZz.git
```

#### 1.1. Use BuildScript for iOS 64 & Simulator 64

```
cd BuildScript
sh ./build_64_fat_macho.sh
```

#### 1.2. Build for iOS/ARM64

```
mkdir temp_build_aarch64

cd temp_build_aarch64

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


#### 1.3. Build for Android, `arm64-v8a`

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

cmake .. \
-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
-DCMAKE_BUILD_TYPE=Release \
-DANDROID_ABI="arm64-v8a" \
-DANDROID_NATIVE_API_LEVEL=android-21 \
-DSHARED=ON \
-DHOOKZZ_DEBUG=OFF

make -j4
```

#### 1.4. Build for Android, `armeabi-v7a`

```
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle

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

## 2. Example

#### 2.1. Example for iOS 64 & Simulator 64

Ref: [iOS/AArch64.ARMv8](examples/iOS/AArch64.ARMv8)

#### 2.2. for HOST

Ref: [HOST](examples/HookSimpleFunction)

use `cmake ..` is done.


## 3. Usage

#### 3.1. replace hook function

```
extern "C" {
  extern int ZzReplace(void *function_address, void *replace_call, void **origin_call);
}

size_t (*origin_fread)(void * ptr, size_t size, size_t nitems, FILE * stream);

size_t (fake_fread)(void * ptr, size_t size, size_t nitems, FILE * stream) {
    // Do What you Want.
    return origin_fread(ptr, size, nitems, stream);
}

void hook_fread() {
    ZzReplace((void *)fread, (void *)fake_fread, (void **)&origin_fread);
}
```

## 4. Known Issues

#### 4.1. Android / ARM

4.1.1. not fixed `pld`

#### 4.2 x86

`x86_64` is tested, but not `x86`.

## 5. Refer
1. [frida-gum](https://github.com/frida/frida-gum) 
2. [minhook](https://github.com/TsudaKageyu/minhook) 
3. [substrate](https://github.com/jevinskie/substrate).
4. [v8](https://github.com/v8/v8)
5. [dart](https://github.com/dart-lang/sdk)
6. [vixl](https://git.linaro.org/arm/vixl.git)

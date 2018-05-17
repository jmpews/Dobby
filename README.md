[转到中文README](README_zh-cn.md)

## What is HookZz ?

**a hook framework for arm/arm64/ios/android**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to [frida-gum](https://github.com/frida/frida-gum) perfect code and modular architecture, frida is aircraft carrier, HookZz is boat, but still with some tricks**

**thanks for @lauos with contributing android code**

## Features

- **solidify inlinehook without Jailbreak(Static Binary Instrumentation) [new-90%]**

- **GOT hook with HookZz(i.e. change fishhook to inlinehook), better for APM**

- the power to access registers directly

- hook function with `replace_call`

- hook function with `pre_call` and `post_call`

- hook **address(a piece of instructions)** with `pre_call` and `half_call`

- (almost)only **one instruction** to hook(i.e. hook **short funciton, even only one instruction**) [arm/thumb/arm64]

- runtime code patch, without codesign limit [Jailbreak]

- it's cute, **100kb**

## Compile

#### Cmake

**`git clone --depth 1 git@github.com:jmpews/HookZz.git`**

#### CMake is bettter(hmmm, maybe some option you need modify by yourself)

```
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
```

#### iOS

just `make clean; make BACKEND=ios ARCH=arm64`

#### Android

`ndkbuild` or use `Android Studio`

## How it works ?

[Move to HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/docs/HookFrameworkDesign.md)

## Demo

#### iOS

[DemoTemplate.zip](https://github.com/jmpews/HookZz/blob/master/demo/iOS/DemoTemplate.zip)

#### Android

[HookZzAndroidDemoTemplate.zip](https://github.com/jmpews/HookZz/blob/master/demo/HookZzAndroidDemoTemplate.zip)

## Thanks List

@sxf144 - RMB1000

@ckis - RMB88

## Contact Me

```
recommend_email: jmpews@gmail.com
wechat: winter1ife
QQ: 858982985
```

<img with="320px" height="320px" src="http://ww1.sinaimg.cn/large/a4decaedgy1frev72yg6mj20iq0owabp.jpg" alt="qrcode">

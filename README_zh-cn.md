## HookZz 简介

一款适用于 arm/arm64 架构, 针对 ios/android 的 Hook 框架.

代码上借鉴了 [frida-gum](https://github.com/frida/frida-gum) & [minhook](https://github.com/TsudaKageyu/minhook) & [substrate](https://github.com/jevinskie/substrate)

这里特别感谢 [frida-gum](https://github.com/frida/frida-gum), `frida-gum` 具有非常优秀的代码架构和精妙的代码, 与 `frida-gum` 这个庞大的航空母舰相比, `HookZz` 太弱小. 但有时候也许你可能只是需要一把锋利的小刀.

这里特别感谢 @lauos 贡献部分的 android 代码.

## 特点

- **静态化 Hook aka 静态二进制插桩, 可以静态 Patch 文件**
- **GOT Hook 但执行 HookZz 的流程, 对 APM 有帮助**
- 操作寄存器的能力
- 直接替换函数
- 为目标函数添加 `pre_call` 和 `post_call` 处理
- 动态插桩 aka 指令级 Hook
- 动态代码 Patch
- 很小 aka 100kb

## 编译

注意: 请不要使用 `build.sh`, 只是未完成的占位符文件.

需要先 clone 工程 **`git clone --depth 1 git@github.com:jmpews/HookZz.git`**

#### CMake 更好一些 (你可能需要做一些调整)

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

`make clean; make BACKEND=ios ARCH=arm64` 编译后的文件在 `build` 目录内

#### Android

可以使用 `ndkbuild` 或者使用 `Android Studio` 整合进入您的工程, 详情见 `Demo`

## HookZz 原理

可以参考文档 [HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/docs/HookFrameworkDesign.md)

## Demo 工程

#### iOS

#### Android

可以参考 [HookZzAndroidDemoTemplate.zip](https://github.com/jmpews/HookZz/blob/master/demo/HookZzAndroidDemoTemplate.zip)


## 联系我

```
recommend_email: jmpews@gmail.com
wechat: winter1ife
QQ: 858982985
```

<img with="320px" height="320px" src="http://ww1.sinaimg.cn/large/a4decaedgy1fs87lnda3ej20iq0ow0ue.jpg" alt="qrcode">

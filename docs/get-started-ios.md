# Getting Started With iOS

available build option within iOS:

## add Dobby.framework to your project

```
cmake .. -G Xcode \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DPLATFORM=OS64 -DARCHS="arm64" -DCMAKE_SYSTEM_PROCESSOR=arm64 \
-DENABLE_BITCODE=0 -DENABLE_ARC=0 -DENABLE_VISIBILITY=1 -DDEPLOYMENT_TARGET=9.3 \
-DDOBBY_GENERATE_SHARED=OFF -DGenerateDarwinFramework=ON

```

**drag the `Dobby.xcodeproj` to your project**


## replace hook function

ref source `builtin-plugin/ApplicationEventMonitor/dynamic_loader_monitor.cc`

ref source `builtin-plugin/ApplicationEventMonitor/posix_file_descriptor_operation_monitor.cc`

## instrument function

ref source `builtin-plugin/ApplicationEventMonitor/MGCopyAnswerMonitor.cc`

## replace pac function

```
void *posix_spawn_ptr = __builtin_ptrauth_strip((void *)posix_spawn, ptrauth_key_asia);
void *fake_posix_spawn_ptr = __builtin_ptrauth_strip((void *)fake_posix_spawn, ptrauth_key_asia);

DobbyHook((void *)posix_spawn_ptr, (void *)fake_posix_spawn_ptr, (void **)&orig_posix_spawn);

*(void **)&orig_posix_spawn = (void *)ptrauth_sign_unauthenticated((void *)orig_posix_spawn, ptrauth_key_asia, 0);
```


## objective-c toolkit

invoke `DobbyOCReturnConstant("XXClass", "isVip", true);` will hook the objective-c instance/class method, and return the constant 1 automatically.

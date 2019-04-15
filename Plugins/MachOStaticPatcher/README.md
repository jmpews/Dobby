## Prologue

MachOSaticPatcher is a static hook tool which is based on HookZz.

## Compile & Build

#### 1. Build `MachOStaticPatcher` Executable

`MachOStaticPatcher` modify and insert an indirect branch stub at the target function which you want to hook. It's not enough, so RuntimeSupport library is necessary at runtime.

```
cd HookZz/Plugins/MachOStaticPatcher

mkdir build

cmake .. -DHOOKZZ_SOURCE_DIR=/path/HookZz

make -j4
```

final, you found the `MachOStaticPatcher` executable

#### 2 Build `RuntimeSupport` Library

The `RuntimeSupport` library do some auxiliary work and provide interface function(ZzReplaceStatic).

You can use any one way below.

**Choice 1:** Build `RuntimeSupport` as the library

```
cd HookZz/Plugins/MachOStaticPatcher/RuntimeSupport

mkdir build

cmake .. -DCMAKE_TOOLCHAIN_FILE=${HOOKZZ_SOURCE_DIR}/cmake/ios.toolchain.cmake -DPLATFORM=OS64 -DARCHS=arm64 -DENABLE_BITCODE=0 -DENABLE_ARC=0 -DENABLE_VISIBILITY=0 -DDEPLOYMENT_TARGET=9.3 -DCMAKE_SYSTEM_PROCESSOR=aarch64

make
```

add `libRuntimeSupport.dylib` to your project.


**Choice 2:** Add the source file to your hack lib.

add `FunctionInlineReplaceExport.cc`, `StubRebase.cc`, `internal.h` to your project.


## Use `MachOStaticPathcer` to insert indirect branch stub.

#### 0. Check the origin code signature

```
codesign --verify --verbose=3 /YourBinaryApp
```

#### 1. Remove the origin code signature.

```
codesign --remove-signature /YourBinaryApp/Binary
```

#### 2. Static insert indirect branch stub to your binary

`function_vmaddr` is the virtual function address which is the same as the IDA pro show.

```
./MachOStaticPatcher /YourBinaryApp/binary function_vmaddr1 function_vmaddr2
```

#### 3. Resign the binary

```
# dump the entitlements.plist
security cms -D -i /YourBinaryApp/embedded.mobileprovision > profile.plist
/usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist

# force resign the app
codesign -f -s "iPhone Developer: Haolin Huang (xxxxxx)" --entitlements entitlements.plist /YourBinaryApp
```

#### 4. Not done yet.

static patch the binary is done, but the stub content is a virtual address, so the RuntimeSupport do some `rebase` work which like `dyld`.

## Use `RuntimeSupport` library


As I mentioned above, add the `RuntimeSupport` to your hack lib on your way.

So, Now you can hook target function as.

```
ZzReplaceStatic("binary_image_name", function_vmaddr, your_fake_function);
```

## Use `OneKey` Xcode Run Script

config the `OneKey/auto.sh`, and add it to the Xcode run script

## Epilogue

have fun.
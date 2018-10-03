# HookZz  [![](https://img.shields.io/badge/chat-on--discord-7289da.svg?style=flat-square&longCache=true&logo=discord)](https://discord.gg/P4uCTTH)

A hook framework for arm / arm64 / iOS / Android

| Branch Type | Arch/Mode | Trampoline Assembly | Bytes | Range |
| - | - | - | - | - |
| NearBranch | ARM64 | `b xxx` | 4 | 2^25 |
| FarBranch | ARM64 | `ldr x17, 8`<br>`br x17`<br>`.long 0x?`<br>`.long 0x?` | 16 | 2^64 |
| NearBranch | ARM/ARM | `b 0x?` | 4 | 2^25 |
| FarBranch | ARM/ARM | `ldr pc, [pc, #-4]`<br>`.long 0x?` | 8 | 2^32 |
| NearBranch | ARM/Thumb1 | `b 0x?` | 2 | 2^6 |
| NearBranch | ARM/Thumb2 | `b 0x?` | 4 | 2^25 |
| FarBranch | ARM/Thumb2 | `ldr pc, [pc, #-[2\|4]`<br>`.long 0x?` | 8 | 2^32 |

## Features

- Static Binary Instrumentation for Mach-O [doing]

- GOT hook with `pre_call` & `post_call`

- **replace function** with `replace_call`

- **wrap function** with `pre_call` and `post_call`

- **dynamic binary instrumentation** with `dbi_call`

- the power to hook short function 

- the power to access registers directly(ex: `reg_ctx->general.regs.x15`)

- runtime code patch

- it's cute, **<100kb**

## Compile

**`git clone --depth 1 git@github.com:jmpews/HookZz.git --branch master`**

#### Build for iOS/ARM64

```
mkdir build
cd build
cmake .. \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DIOS_PLATFORM=OS \
-DIOS_ARCH=arm64 \
-DENABLE_ARC=FALSE \
-DENABLE_BITCODE=OFF \
-DCXX=OFF \
-DX_ARCH=arm64 \
-DX_PLATFORM=iOS \
-DX_SHARED=ON \
-DX_LOG=ON \
-DCMAKE_VERBOSE_MAKEFILE=OFF
make
```

if you want generate Xcode Project, just replace with `cmake -G Xcode `.

#### build for Android/ARM64

```
mkdir build
cd build
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle
cmake .. \
-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
-DANDROID_NDK=$ANDROID_NDK \
-DCMAKE_BUILD_TYPE=Release \
-DANDROID_ABI=arm64-v8a \
-DCXX=OFF \
-DX_ARCH=arm64 \
-DX_PLATFORM=Android \
-DX_SHARED=ON \
-DX_LOG=ON \
-DCMAKE_VERBOSE_MAKEFILE=OFF
```

## Demo
#### Android/ARMv8

https://github.com/jmpews/HookZzAndroidDemo

## Usage
#### 0. near jump

this trick is used to hook short function. it will use `b xxx` replace

```
ldr x17, #8
br x17
.long 0x1111
.long 0x1111
````

if you want enable near jump, just add `zz_enable_near_jump();` before hook funciton, and stop with `zz_disable_near_jump();`

#### 1. replace hook function
```
RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call);

size_t (*origin_fread)(void * ptr, size_t size, size_t nitems, FILE * stream);
size_t (fake_fread)(void * ptr, size_t size, size_t nitems, FILE * stream) {
    printf("[FileMonitor|fread|model|%p] >>> %ld, %ld\n", ptr, size, nitems);
    return origin_fread(ptr, size, nitems, stream);
}

void hook_fread() { ZzReplace((void *)fread, (void *)fake_fread, (void **)&origin_fread); }
```

#### 2. wrap hook function
```
RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call);

void open_pre_call(RegisterContext *reg_ctx, ThreadStackPublic *tsp, CallStackPublic *csp, const HookEntryInfo *info) {
    char *path = (char *)reg_ctx->ZREG(0);
    int oflag  = (int)reg_ctx->ZREG(1);

    if (pathFilter(path))
        return;
    
    switch (oflag) {
    case O_RDONLY:
        printf("[FileMonitor|open|R] >>> %s\n", path);
        break;
    case O_WRONLY:
        printf("[FileMonitor|open|W] >>> %s\n", path);
        break;
    case O_RDWR:
        printf("[FileMonitor|open|RW] >>> %s\n", path);
        break;
    default:
        printf("[FileMonitor|open|-] >>> %s\n", path);
        break;
    }
}

void open_post_call(RegisterContext *reg_ctx, ThreadStackPublic *tsp, CallStackPublic *csp, const HookEntryInfo *info) {
}

void hook_open() { ZzWrap((void *)open, open_pre_call, open_post_call); }
```

#### 3. dynamic binary instrumentation
```
RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL dbi_call);

void catchDecrypt(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  printf("descrypt catch by HookZz\n");
}

__attribute__((constructor)) void initlializeTemplate() {
    struct mach_header *mainHeader = (struct mach_header *)_dyld_get_image_header(0);
    int slide                      = _dyld_get_image_vmaddr_slide(0);
    uintptr_t targetVmAddr         = 0x1001152BC;
    uintptr_t finalAddr            = targetVmAddr + slide - 0x0000000000002170;
    
    printf(">>> ASLR: 0x%x\n", slide);
    printf(">>> decrypt address: %p\n", (void *)finalAddr);
    ZzDynamicBinaryInstrumentation((void *)finalAddr, catchDecrypt);
}

#### Refer

1. [frida-gum](https://github.com/frida/frida-gum) 
2. [minhook](https://github.com/TsudaKageyu/minhook) 
3. [substrate](https://github.com/jevinskie/substrate).
4. [v8](https://github.com/v8/v8)
5. [dart](https://github.com/dart-lang/sdk)
6. [vixl](https://git.linaro.org/arm/vixl.git)

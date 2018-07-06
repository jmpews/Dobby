此分支为重构分支仅支持 iOS/ARM64 | [转到分支MASTER(need update)](https://github.com/jmpews/HookZz/tree/master)

## What is HookZz ?

**a hook framework for arm/arm64/ios/android**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to [frida-gum](https://github.com/frida/frida-gum) perfect code and modular architecture, frida is aircraft carrier, HookZz is boat, but still with some tricks**

## Features

- Static Binary Instrumentation for Mach-O [doing]

- GOT hook with `pre_call` & `post_call`

- **replace function** with `replace_call`

- **wrap function** with `pre_call` and `post_call`

- **dynamic binary instrumentation** with `dbi_call`

- the power to hook short function 

- the power to access registers directly(ex: `rs->general.regs.x15`)

- runtime code patch

- it's cute, **100kb**

## Compile

**`git clone --depth 1 git@github.com:jmpews/HookZz.git --branch master-c`**

#### build for iOS/ARM64

```
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake -DIOS_PLATFORM=OS -DIOS_ARCH=arm64 -DENABLE_ARC=FALSE -DENABLE_BITCODE=OFF -DX_ARCH=arm64 -DX_PLATFORM=iOS -DCXX=OFF -DX_SHARED=ON -DX_LOG=ON -DCMAKE_VERBOSE_MAKEFILE=OFF
make
```

if you want generate Xcode Project, just replace with `cmake -G Xcode .. -DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake -DIOS_PLATFORM=OS -DIOS_ARCH=arm64 -DENABLE_ARC=FALSE -DENABLE_BITCODE=OFF -DX_ARCH=arm64 -DX_PLATFORM=iOS -DCXX=OFF -DX_SHARED=ON -DX_LOG=ON -DCMAKE_VERBOSE_MAKEFILE=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.

#### build for Android/ARM64

```
mkdir build
cd build
export ANDROID_NDK=/Users/jmpews/Library/Android/sdk/ndk-bundle
cmake .. -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_NDK=$ANDROID_NDK -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI=arm64-v8a -DX_ARCH=arm64 -DX_PLATFORM=iOS -DCXX=OFF -DX_SHARED=ON -DX_LOG=ON -DCMAKE_VERBOSE_MAKEFILE=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

## Usage

#### 1. replace hook function
```
RetStatus ZzReplace(void *function_address, void *replace_call, void **origin_call);

size_t (*origin_fread)(void * ptr, size_t size, size_t nitems, FILE * stream);
size_t (fake_fread)(void * ptr, size_t size, size_t nitems, FILE * stream) {
    std::vector<FILE *>::iterator it = std::find(modelFileDescriptors.begin(), modelFileDescriptors.end(), stream);
    if(it != modelFileDescriptors.end()) {
        printf("[FileMonitor|fread|model|%p] >>> %ld, %ld\n", ptr, size, nitems);
    }
    return origin_fread(ptr, size, nitems, stream);
}

void hook_fread() { ZzReplace((void *)fread, (void *)fake_fread, (void **)&origin_fread); }
```

#### 2. wrap hook function
```
RetStatus ZzWrap(void *function_address, PRECALL pre_call, POSTCALL post_call);

void open_pre_call(RegState *rs, ThreadStackPublic *tsp, CallStackPublic *csp, const HookEntryInfo *info) {
    char *path = (char *)rs->ZREG(0);
    int oflag  = (int)rs->ZREG(1);

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

void open_post_call(RegState *rs, ThreadStackPublic *tsp, CallStackPublic *csp, const HookEntryInfo *info) {
}

void hook_open() { ZzWrap((void *)open, open_pre_call, open_post_call); }
```

#### 3. dynamic binary instrumentation
```
RetStatus ZzDynamicBinaryInstrumentation(void *inst_address, DBICALL dbi_call);

void catchDecrypt(RegState *rs, const HookEntryInfo *info) {
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

```

## Contact Me

```
recommend_email: jmpews@gmail.com
QQ: 858982985
```

<img with="220px" height="220px" src="http://ww1.sinaimg.cn/large/a4decaedgy1fsum2d3fl2j20gq0gm41i.jpg" alt="qrcode">

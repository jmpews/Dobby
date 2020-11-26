## Dobby 

[![Contact me Telegram](https://img.shields.io/badge/Contact%20me-Telegram-blue.svg)](https://t.me/RadeonRayTrace) [![Join group Telegram](https://img.shields.io/badge/Join%20group-Telegram-brightgreen.svg)](https://t.me/dobby_group)  

Dobby a lightweight, multi-platform, multi-architecture exploit hook framework.

- Minimal and modular library
- Multi-platform support(Windows/macOS/iOS/Android/Linux)
- Multiple architecture support(X86, X86-64, ARM, ARM64)
- Clean code without STL(port to kernel easily)
- Plugin support(SymbolResolver, SupervisorCallMonitor)
- iOS kernel exploit support(Gollum ?)

## Getting started

```
git clone https://github.com/jmpews/Dobby.git --depth=1
cd Dobby/example/
mkdir build; cd build; cmake ..
```

Or download [latest release](https://github.com/jmpews/Dobby/releases/tag/latest)

#### [Build Installation](docs/build-documentation.md)

#### [Getting Started with iOS](docs/get-started-ios.md)

#### [Getting Started with Android](docs/get-started-android.md)

## Quick demo

#### iOS ARM64E

```
void *posix_spawn_ptr = __builtin_ptrauth_strip((void *)posix_spawn, ptrauth_key_asia);
void *fake_posix_spawn_ptr = __builtin_ptrauth_strip((void *)fake_posix_spawn, ptrauth_key_asia);
DobbyHook((void *)posix_spawn_ptr, (void *)fake_posix_spawn_ptr, (void **)&orig_posix_spawn);
*(void **)&orig_posix_spawn = (void *)ptrauth_sign_unauthenticated((void *)orig_posix_spawn, ptrauth_key_asia, 0);
```

#### Android Linker Restriction

```
# impl at SymbolResolver/elf/dobby_symbol_resolver.cc
void *__loader_dlopen = DobbySymbolResolver(NULL, "__loader_dlopen");
DobbyHook((void *)__loader_dlopen, (void *)fake_loader_dlopen, (void **)&orig_loader_dlopen);
```

```
# impl at AndroidRestriction/android_restriction.cc
linker_disable_namespace_restriction();
void *handle = NULL;
handle       = dlopen(lib, RTLD_LAZY);
vm           = dlsym(handle, "_ZN7android14AndroidRuntime7mJavaVME");
```

## Documentation

[full Installation documentation site](http://dobby.libkernel.com)

## Download

[download static library](https://github.com/jmpews/Dobby/releases/tag/latest)

## Credits

1. [frida-gum](https://github.com/frida/frida-gum)
2. [minhook](https://github.com/TsudaKageyu/minhook)
3. [substrate](https://github.com/jevinskie/substrate).
4. [v8](https://github.com/v8/v8)
5. [dart](https://github.com/dart-lang/sdk)
6. [vixl](https://git.linaro.org/arm/vixl.git)

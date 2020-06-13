## Dobby

Dobby a lightweight, multi-platform, multi-architecture exploit hook framework.

- Minimal and modular library
- Multi-platform support(Windows/macOS/iOS/Android/Linux)
- Multiple architecture support(X86-64, ARM, ARM64)
- Clean code without STL(port to kernel easily)
- Plugin support(DobbyDrill ?)
- iOS kernel exploit support(Gollum ?)

## Getting started

```
git clone https://github.com/jmpews/Dobby.git --depth=1
cd Dobby/example/
mkdir build; cd build; cmake ..
```

```
void *posix_spawn_ptr = __builtin_ptrauth_strip((void *)posix_spawn, ptrauth_key_asia);
void *fake_posix_spawn_ptr = __builtin_ptrauth_strip((void *)fake_posix_spawn, ptrauth_key_asia);
DobbyHook((void *)posix_spawn_ptr, (void *)fake_posix_spawn_ptr, (void **)&orig_posix_spawn);
*(void **)&orig_posix_spawn = (void *)ptrauth_sign_unauthenticated((void *)orig_posix_spawn, ptrauth_key_asia, 0);
```

## Documentation

[full Installation documentation site](http://dobby.libkernel.com)

## Credits

1. [frida-gum](https://github.com/frida/frida-gum)
2. [minhook](https://github.com/TsudaKageyu/minhook)
3. [substrate](https://github.com/jevinskie/substrate).
4. [v8](https://github.com/v8/v8)
5. [dart](https://github.com/dart-lang/sdk)
6. [vixl](https://git.linaro.org/arm/vixl.git)

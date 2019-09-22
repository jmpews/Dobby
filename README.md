# HookZz [![](https://img.shields.io/badge/chat-on--discord-7289da.svg?style=flat-square&longCache=true&logo=discord)](https://discordapp.com/invite/P4uCTTH)

**if you have any question [go to Discord](https://discordapp.com/invite/P4uCTTH) or [full documentation here](http://hookzz.libkernel.com/)**

**HookZz still in beta**

## Installation

#### build for host machine
```
git clone --branch dev --depth 1 https://github.com/jmpews/HookZz.git

cd HookZz && mkdir build && cd build && cmake .. && make
```

#### build for others (iOS / Android / ARM / ARM64)

-> [full Installation documents](./docs/installation.md) or [full Installation document site](http://hookzz.libkernel.com)

## Usage and Example

#### simple replace hook function

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

#### multi-platform example

- [iOS](./examples/iOS)

- [HOST](./examples)


## Known Issues

#### Android / ARM

4.1.1. not fixed `pld`

#### x86

`x86_64` tested, but not `x86`.

## Refer

1. [frida-gum](https://github.com/frida/frida-gum) 
2. [minhook](https://github.com/TsudaKageyu/minhook) 
3. [substrate](https://github.com/jevinskie/substrate).
4. [v8](https://github.com/v8/v8)
5. [dart](https://github.com/dart-lang/sdk)
6. [vixl](https://git.linaro.org/arm/vixl.git)

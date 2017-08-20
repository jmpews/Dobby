# HookZz

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZz Example](https://jmpews.github.io/zzpp/hookzz-example/)

> [Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)

# What is HookZz ?

**a cute hook framwork**. 

**still developing, for arm64/IOS now!**

ref to: [frida-gum](https://github.com/frida/frida-gum) and [minhook](https://github.com/TsudaKageyu/minhook) and [substrate](https://github.com/jevinskie/substrate).

**special thanks to `frida-gum's` perfect code and modular architecture, and hookzz just like a toy in front of frida**

# Features

- [hookzz-modules](https://github.com/jmpews/HookZzModules)

- hook function with `replace_call`

- hook function with `pre_call` and `post_call`

- hook **address(a piece of code)** with `pre_call` and `half_call`

- runtime code patch work with [MachoParser](https://github.com/jmpews/MachoParser),without codesign limit

- it's cute

# Getting Started

[Move to HookZz Getting Started](https://github.com/jmpews/HookZz/blob/master/HookFrameworkDesign.md)

# How it works ?

[Move to HookFrameworkDesign.md](https://github.com/jmpews/HookZz/blob/master/HookFrameworkDesign.md)

# Docs

[Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

# Example

[Move to HookZz example](https://jmpews.github.io/zzpp/hookzz-example/)

# Compile

now only for `arm64/ios`.

#### build `libhookzz.static.a` and `libhookzz.dylib` for arm64(ios)

```
λ : >>> make -f darwin.ios.mk darwin.ios
generate [src/allocator.o]!
generate [src/interceptor.o]!
generate [src/memory.o]!
generate [src/stack.o]!
generate [src/trampoline.o]!
generate [src/platforms/darwin/memory-darwin.o]!
generate [src/platforms/arm64/reader.o]!
generate [src/platforms/arm64/relocator.o]!
generate [src/platforms/arm64/thunker.o]!
generate [src/platforms/arm64/writer.o]!
generate [src/zzdeps/darwin/macho-utils-darwin.o]!
generate [src/zzdeps/darwin/memory-utils-darwin.o]!
generate [src/zzdeps/common/memory-utils-common.o]!
generate [src/zzdeps/posix/memory-utils-posix.o]!
generate [src/zzdeps/posix/thread-utils-posix.o]!
build success for arm64(IOS)!
```

#### build test for arm64(ios)

```
λ : >>> make -f darwin.ios.mk test
build success for arm64(IOS)!
build [test_hook_oc.dylib] success for arm64(ios)!
build [test_hook_address.dylib] success for arm64(ios)!
build [test] success for arm64(IOS)!
```

> temporary move here

# Compile

use `git clone --depth 1 http://github.com/jmpews/HookZz` to clone the latest commit.

## build for arm64-ios

#### 1. build `libhookzz.dylib` and `libhookzz.static.a`

```
λ : >>> make clean; make BACKEND=ios ARCH=arm64
clean all *.o success!
generate [/Users/jmpews/project/HookZz/src/allocator.o]!
generate [/Users/jmpews/project/HookZz/src/interceptor.o]!
generate [/Users/jmpews/project/HookZz/src/memory.o]!
generate [/Users/jmpews/project/HookZz/src/stack.o]!
generate [/Users/jmpews/project/HookZz/src/tools.o]!
generate [/Users/jmpews/project/HookZz/src/trampoline.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/backend-posix/thread-posix.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/backend-darwin/memory-darwin.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/arch-arm64/instructions.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/arch-arm64/reader-arm64.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/arch-arm64/regs-arm64.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/arch-arm64/relocator-arm64.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/arch-arm64/writer-arm64.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/backend-arm64/interceptor-arm64.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/backend-arm64/thunker-arm64.o]!
generate [/Users/jmpews/project/kitzz/CommonKit/memory/common_memory_kit.o]!
generate [/Users/jmpews/project/kitzz/PosixKit/memory/posix_memory_kit.o]!
generate [/Users/jmpews/project/kitzz/PosixKit/thread/posix_thread_kit.o]!
generate [/Users/jmpews/project/kitzz/MachoKit/macho_kit.o]!
generate [/Users/jmpews/project/kitzz/DarwinKit/MemoryKit/darwin_memory_kit.o]!
generate [/Users/jmpews/project/HookZz/src/platforms/backend-arm64/interceptor-template-arm64.o]!
build success for arm64-ios-hookzz!
```

check `build/ios-arm64/*`.

#### 2. build tests dylib

```
λ : >>> make clean; make
clean all *.o success!
build [test_hook_oc.dylib] success for arm64-ios!
build [test_hook_address.dylib] success for arm64-ios!
build [test_hook_printf.dylib] success for arm64-ios!
build [test] success for arm64-ios-hookzz!
```

check `build/ios-arm64/*`.

## build for arm-ios

ignore...

## build for arm64-android

use ndk-build

#### build `libhookzz.so` and `libhookzz.static.a`

```
λ D:\TechnicalProgram\Android-SDK\ndk-bundle\build\ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_ABI=arm64-v8a
Android NDK: APP_PLATFORM not set. Defaulting to minimum supported version android-14.
[arm64-v8a] Compile        : hookzz <= allocator.c
[arm64-v8a] Compile        : hookzz <= interceptor.c
[arm64-v8a] Compile        : hookzz <= memory.c
[arm64-v8a] Compile        : hookzz <= stack.c
[arm64-v8a] Compile        : hookzz <= tools.c
[arm64-v8a] Compile        : hookzz <= trampoline.c
[arm64-v8a] Compile        : hookzz <= memory-linux.c
[arm64-v8a] Compile        : hookzz <= thread-posix.c
[arm64-v8a] Compile        : hookzz <= instructions.c
[arm64-v8a] Compile        : hookzz <= reader-arm64.c
[arm64-v8a] Compile        : hookzz <= regs-arm64.c
[arm64-v8a] Compile        : hookzz <= relocator-arm64.c
[arm64-v8a] Compile        : hookzz <= writer-arm64.c
[arm64-v8a] Compile        : hookzz <= interceptor-arm64.c
[arm64-v8a] Compile        : hookzz <= thunker-arm64.c
[arm64-v8a] Compile        : hookzz <= interceptor-template-arm64.S
[arm64-v8a] Compile        : hookzz <= common_memory_kit.c
[arm64-v8a] Compile        : hookzz <= linux_memory_kit.c
[arm64-v8a] Compile        : hookzz <= posix_memory_kit.c
[arm64-v8a] Compile        : hookzz <= posix_thread_kit.c
[arm64-v8a] StaticLibrary  : libhookzz.a
```

#### build tests ELF

test files in `tests/arm-android`

# Quick Example

#### `test_hook_printf.c` output for arm64-ios

test hook `printf` with `try_near_jump` option , and `ZzEnableDebugMode()` with `replace_call`, `pre_call`, `post_call`.

```
ZzThunkerBuildThunk:
LogInfo: enter_thunk at 0x100162c20, use enter_thunk_template.

ZzThunkerBuildThunk:
LogInfo: leave_thunk at 0x1001500f4, length: 240.

ZzBuildEnterTrampoline:
LogInfo: on_enter_trampoline at 0x1001502d8, length: 44. hook-entry: 0x145e0c720. and will jump to enter_thunk(0x100162c20).

ZzBuildEnterTransferTrampoline:
LogInfo: on_enter_transfer_trampoline at 0x180f1f414, length: 20. and will jump to on_enter_trampoline(0x1001502d8).

ZzBuildInvokeTrampoline:
LogInfo: on_invoke_trampoline at 0x100150304, length: 24. and will jump to rest code(0x181402a60).
ARMInstructionFix: origin instruction at 0x181402a5c, relocator end at 0x181402a60, relocator instruction nums 1
origin_prologue: 0xf4 0x4f 0xbe 0xa9 

ZzBuildLeaveTrampoline:
LogInfo: on_leave_trampoline at 0x10015031c, length: 44. and will jump to leave_thunk(0x1001500f4).

HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

printf-pre-call
call printf
HookZzzzzzz, 1, 0x2, 3, 4, 5, 6, 7, 8, 9
HookZzzzzzz, %d, %p, %d, %d, %d, %d, %d, %d, %d

printf-post-call
```

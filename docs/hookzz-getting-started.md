# HookZz Getting Started

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZz Example](https://jmpews.github.io/zzpp/hookzz-example/)

> [Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)

# 1. build hookzz dylib

clone the repo `git clone https://github.com/jmpews/HookZz` and build for `darwin.ios`. btw, you can set the log infomation level in `src/zz.h`.

```
λ : >>> make -f darwin.ios.mk darwin.ios
generate [src/allocator.o]!
generate [src/interceptor.o]!
generate [src/memory.o]!
generate [src/stack.o]!
generate [src/thread.o]!
generate [src/trampoline.o]!
generate [src/platforms/posix/thread-posix.o]!
generate [src/platforms/darwin/memory-darwin.o]!
generate [src/platforms/arm64/reader.o]!
generate [src/platforms/arm64/relocator-arm64.o]!
generate [src/platforms/arm64/thunker-arm64.o]!
generate [src/platforms/arm64/writer-arm64.o]!
generate [src/zzdeps/darwin/macho-utils-darwin.o]!
generate [src/zzdeps/darwin/memory-utils-darwin.o]!
generate [src/zzdeps/common/memory-utils-common.o]!
generate [src/zzdeps/posix/memory-utils-posix.o]!
generate [src/zzdeps/posix/thread-utils-posix.o]!
build success for arm64(IOS)!
```

check the dylibs in `build` directory. `libhookzz.dylib` is shared library, and `libhookzz.static.a` is static library.

```
λ : >>> ls build
libhookzz.dylib    libhookzz.static.a
```

# 2. build the test demo dylib

a demo dylib to hook `[UIViewController viewWillAppear]`

before build demo dylib, specify the hookzz library path(shared or static).

1. build with commandline.

```
`xcrun --sdk iphoneos --find clang` -isysroot `xcrun --sdk iphoneos --show-sdk-path` -g -gmodules -I/path/HookZz/include  -L/path/HookZz/build -lhookzz.static -framework Foundation -dynamiclib -arch arm64 test_hook_oc.m -o test_hook_oc.dylib
```

2. build with `make -f darwin.ios.mk test`

```
λ : >>> make -f darwin.ios.mk test
build success for arm64(IOS)!
build [test_hook_oc.dylib] success for arm64(ios)!
build [test_hook_address.dylib] success for arm64(ios)!
build [test] success for arm64(IOS)!
```

```
jmpews at localhost in ~/Desktop/SpiderZz/project/HookZz (master●) (normal)
λ : >>> ls build
libhookzz.dylib         libhookzz.static.a      test_hook_address.dylib test_hook_oc.dylib
```

```
#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
  [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
  zpointer t = 0x1234; 
  STACK_SET(callstack ,"key_x", t, void *);
  STACK_SET(callstack ,"key_y", t, zpointer);
  NSLog(@"hookzz OC-Method: -[UIViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

void objcMethod_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
  zpointer x = STACK_GET(callstack, "key_x", void *);
  zpointer y = STACK_GET(callstack, "key_y", zpointer);
  NSLog(@"function over, and get 'key_x' is: %p", x);
  NSLog(@"function over, and get 'key_y' is: %p", y);
}

+ (void)zzMethodSwizzlingHook {
  Class hookClass = objc_getClass("UIViewController");
  SEL oriSEL = @selector(viewWillAppear:);
  Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
  IMP oriImp = method_getImplementation(oriMethod);

  ZzBuildHook((void *)oriImp, NULL, NULL, objcMethod_pre_call, objcMethod_post_call);
  ZzEnableHook((void *)oriImp);

}

@end
```

# 3. test your demo dylib

build new ios app project. and then `Build Phases -> New Run Script Phase` add a run script.

```
cd ${BUILT_PRODUCTS_DIR}
cd ${FULL_PRODUCT_NAME}

cp /path/HookZz/build/test_hook_oc.dylib ./
/usr/bin/codesign --force --sign ${EXPANDED_CODE_SIGN_IDENTITY} --timestamp=none test_hook_oc.dylib
/Users/jmpews/Desktop/SpiderZz/Pwntools/Darwin/bin/optool install -c load -p "@executable_path/test_hook_oc.dylib" -t ${EXECUTABLE_NAME}
```

last thing, run the app ,you will get the such output(with open `GLOBAL_DEBUG`, `GLOBAL_INFO`)

```
target 0x188525804 near jump to 0x183c9141c
target 0x188525804 call begin-invocation
2017-08-20 16:41:26.155 T007[409:129805] hookzz OC-Method: -[ViewController viewWillAppear:]
0x188525804 call end-invocation
2017-08-20 16:41:26.157 T007[409:129805] function over, and get 'key_x' is: 0x1234
2017-08-20 16:41:26.157 T007[409:129805] function over, and get 'key_y' is: 0x1234
```

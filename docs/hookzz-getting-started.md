# HookZz Getting Started

> [Move to HookZz Getting Started](https://jmpews.github.io/zzpp/getting-started/)

> [Move to HookZz Example](https://jmpews.github.io/zzpp/hookzz-example/)

> [Move to HookZz docs](https://jmpews.github.io/zzpp/hookzz-docs/)

> [Move to HookZzModules](https://github.com/jmpews/HookZzModules)

> [Move to HookZzWebsite](https://jmpews.github.io/zzpp/)

# 1. build hookzz dylib

clone the repo `git clone https://github.com/jmpews/HookZz` and build for `darwin.ios`

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
build success for arm64(IOS)!
build [test_hook_oc.dylib] success for arm64(ios)!
build [test_hook_address.dylib] success for arm64(ios)!
build [test] success for arm64(IOS)!

```

```
#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
  [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(RegState *rs, ZzCallerStack *stack) {
  zpointer t = 0x1234; 
  STACK_SET(stack ,"key_x", t, void *);
  STACK_SET(stack ,"key_y", t, zpointer);
  NSLog(@"hookzz OC-Method: -[ViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

void objcMethod_post_call(RegState *rs, ZzCallerStack *stack) {
  zpointer x = STACK_GET(stack, "key_x", void *);
  zpointer y = STACK_GET(stack, "key_y", zpointer);
  NSLog(@"function over, and get 'key_x' is: %p", x);
  NSLog(@"function over, and get 'key_y' is: %p", y);
}
+ (void)zzMethodSwizzlingHook {
  Class hookClass = objc_getClass("UIViewController");
  SEL oriSEL = @selector(viewWillAppear:);
  Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
  IMP oriImp = method_getImplementation(oriMethod);

  ZzInitialize();
  ZzBuildHook((void *)oriImp, NULL, NULL, (zpointer)objcMethod_pre_call, (zpointer)objcMethod_post_call);
  ZzEnableHook((void *)oriImp);
}

@end
```

# 3. test your demo dylib

build new ios app project. and then `Build Phases -> New Run Script Phase` add a run script.

```
cd ${BUILT_PRODUCTS_DIR}
cd ${FULL_PRODUCT_NAME}

cp /path/HookZz/tests/test_hook_oc.dylib ./
/usr/bin/codesign --force --sign ${EXPANDED_CODE_SIGN_IDENTITY} --timestamp=none test_hook_oc.dylib
/Users/jmpews/Desktop/SpiderZz/Pwntools/Darwin/bin/optool install -c load -p "@executable_path/test_hook_oc.dylib" -t ${EXECUTABLE_NAME}
```

last thing, run the app ,you will get the such output.

```
2017-08-10 17:24:10.320124+0800 T007[21070:5375470] docPath: /var/mobile/Containers/Data/Application/9C5D8100-92E6-4722-B491-BC79C9B04FA5/Documents
2017-08-10 17:24:10.320616+0800 T007[21070:5375470] tmpPath: /private/var/mobile/Containers/Data/Application/9C5D8100-92E6-4722-B491-BC79C9B04FA5/tmp/
2017-08-10 17:24:10.320706+0800 T007[21070:5375470] libPath: /var/mobile/Containers/Data/Application/9C5D8100-92E6-4722-B491-BC79C9B04FA5/Library
2017-08-10 17:24:10.320754+0800 T007[21070:5375470] mainPath: /var/containers/Bundle/Application/FBCBF68E-495C-4B62-9A50-001053F452C0/T007.app
2017-08-10 17:24:10.772400+0800 T007[21070:5375470] hookzz OC-Method: -[ViewController viewWillAppear:]
```

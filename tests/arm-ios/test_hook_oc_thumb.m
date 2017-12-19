#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
    [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
    void *t = (void *)0x1234;
    STACK_SET(cs, "key_x", t, void *);
    STACK_SET(cs, "key_y", t, zz_ptr_t);
    NSLog(@"hookzz OC-Method: -[UIViewController %s]",
}

void objcMethod_post_call(RegState *rs, ThreadStack *ts, CallStack *cs, const HookEntryInfo *info) {
    zz_ptr_t x = STACK_GET(cs, "key_x", void *);
    zz_ptr_t y = STACK_GET(cs, "key_y", zz_ptr_t);
    NSLog(@"function over, and get 'key_x' is: %p", x);
}

+ (void)zzMethodSwizzlingHook {
    Class hookClass  = objc_getClass("UIViewController");
    SEL oriSEL       = @selector(viewWillAppear:);
    Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
    IMP oriImp       = method_getImplementation(oriMethod);

    ZzEnableDebugMode();
    ZzHookPrePost((void *)oriImp, objcMethod_pre_call, objcMethod_post_call);
}

@end

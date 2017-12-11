/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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

void objcMethod_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    zz_ptr_t t = 0x1234;
    STACK_SET(callstack, "key_x", t, void *);
    STACK_SET(callstack, "key_y", t, zz_ptr_t);
    NSLog(@"hookzz OC-Method: -[UIViewController %s]", (zz_ptr_t)(rs->general.regs.x1));
}

void objcMethod_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    zz_ptr_t x = STACK_GET(callstack, "key_x", void *);
    zz_ptr_t y = STACK_GET(callstack, "key_y", zz_ptr_t);
    NSLog(@"function over, and get 'key_x' is: %p", x);
    NSLog(@"function over, and get 'key_y' is: %p", y);
}

+ (void)zzMethodSwizzlingHook {
    Class hookClass = objc_getClass("UIViewController");
    SEL oriSEL = @selector(viewWillAppear:);
    Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
    IMP oriImp = method_getImplementation(oriMethod);

    ZzHookPrePost((void *)oriImp, objcMethod_pre_call, objcMethod_post_call);
}

@end

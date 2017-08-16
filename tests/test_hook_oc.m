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

// `xcrun --sdk iphoneos --find clang` -isysroot `xcrun --sdk iphoneos
// --show-sdk-path` -g -gmodules
// -I/Users/jmpews/Desktop/SpiderZz/project/HookZz/include
// -L/Users/jmpews/Desktop/SpiderZz/project/HookZz/build -lhookzz.static
// -framework Foundation -dynamiclib -arch arm64 test_hook_oc.m -o
// test_hook_oc.dylib
#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
  [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(struct RegState_ *rs, ZzCallerStack *stack) {
  zpointer t = 0x1234; 
  ZzCallerStackSet(stack ,"key_x", t);
  ZzCallerStackSet(stack ,"key_y", t);
  NSLog(@"hookzz OC-Method: -[ViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

void objcMethod_post_call(struct RegState_ *rs, ZzCallerStack *stack) {
  zpointer x = ZzCallerStackGet(stack ,"key_x");
  zpointer y = ZzCallerStackGet(stack ,"key_y");
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

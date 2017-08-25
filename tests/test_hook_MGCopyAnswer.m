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
#import <mach-o/dyld.h>
#import <dlfcn.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
  [self hookMGCopyAnswer];
}

void MGCopyAnswer_pre_call(RegState *rs, zpointer stack) {
    CFStringRef request = (CFStringRef)rs->general.regs.x0;
    STACK_SET(stack, "request", request, CFStringRef);
    NSLog(@"request is: %@", request);
}

void MGCopyAnswer_post_call(RegState *rs, zpointer stack) {
    // if(STACK_CHECK_KEY(stack, "request")) {
    //     CFStringRef request = STACK_GET(stack, "request", CFStringRef);
    //     CFPropertyListRef result = (CFPropertyListRef)rs->general.regs.x0;
    //     NSLog(@"result is: %@", result);
    // }
}

static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef prop);
CFPropertyListRef new_MGCopyAnswer(CFStringRef prop) {
    // CFPropertyListRef value = nil;
    // NSString *answerKey = (__bridge NSString *)prop;
    // if (!strcmp(CFStringGetCStringPtr(prop, kCFStringEncodingMacRoman), "UniqueDeviceID")) {
    //     return @"123456";
    // }
    // if (!strcmp(CFStringGetCStringPtr(prop, kCFStringEncodingMacRoman), "CPUArchitecture")) {
    //     return @"123456";
    // }

    return orig_MGCopyAnswer(prop);
}

+ (void)hookMGCopyAnswer {
    void *lib = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    void *symbol_addr = dlsym(lib, "MGCopyAnswer");
    ZzBuildHook((void *)symbol_addr, new_MGCopyAnswer, &orig_MGCopyAnswer, MGCopyAnswer_pre_call, NULL);
    ZzEnableHook((void *)symbol_addr);
}
@end

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

// `xcrun --sdk iphoneos --find clang` -isysroot `xcrun --sdk iphoneos --show-sdk-path` -g -gmodules -I/Users/jmpews/Desktop/SpiderZz/project/HookZz/include  -L/Users/jmpews/Desktop/SpiderZz/project/HookZz/build -lhookzz.static -framework Foundation -dynamiclib -arch arm64 test_hook_oc.m -o test_hook_oc.dylib
#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface HookZz : NSObject

@end

@implementation HookZz

NSString *docPath;
NSString *mainPath;

+ (void)load {
  [self zzPrintDirInfo];
  [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(struct RegState_ *rs) {
  NSLog(@"hookzz OC-Method: -[ViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

+ (void)zzMethodSwizzlingHook {
  Class hookClass = objc_getClass("UIViewController");
  SEL oriSEL = @selector(viewWillAppear:);
  Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
  IMP oriImp = method_getImplementation(oriMethod);

  ZzInitialize();
  ZzBuildHook((void *)oriImp, NULL, NULL, (zpointer)objcMethod_pre_call, NULL);
  ZzEnableHook((void *)oriImp);
}

+ (void)zzPrintDirInfo {
  // 获取Documents目录
  docPath = [NSSearchPathForDirectoriesInDomains(
      NSDocumentDirectory, NSUserDomainMask, YES) lastObject];

  // 获取tmp目录
  NSString *tmpPath = NSTemporaryDirectory();

  // 获取Library目录
  NSString *libPath = [NSSearchPathForDirectoriesInDomains(
      NSLibraryDirectory, NSUserDomainMask, YES) lastObject];

  // 获取Library/Caches目录
  NSString *cachePath = [NSSearchPathForDirectoriesInDomains(
      NSCachesDirectory, NSUserDomainMask, YES) lastObject];

  // 获取Library/Preferences目录
  NSString *prePath = [NSSearchPathForDirectoriesInDomains(
      NSPreferencePanesDirectory, NSUserDomainMask, YES) lastObject];

  // 获取应用程序包的路径
  mainPath = [NSBundle mainBundle].resourcePath;

  NSLog(@"docPath: %@", docPath);
  NSLog(@"tmpPath: %@", tmpPath);
  NSLog(@"libPath: %@", libPath);
  NSLog(@"mainPath: %@", mainPath);
}

+ (bool)zzIsFileExist:(NSString *)filePath {
  NSFileManager *manager = [NSFileManager defaultManager];
  if (![manager fileExistsAtPath:filePath]) {
    NSLog(@"There isn't have the file");
    return YES;
  }
  return FALSE;
}

@end

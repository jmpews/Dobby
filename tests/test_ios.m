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


#import <Foundation/Foundation.h>
#import <dlfcn.h>

@interface SpiderZz: NSObject

@end

@implementation SpiderZz

NSString *docPath;
NSString *mainPath;

+ (void)load
{
    [self zzPrintDirInfo];
    NSString *dylibPath = [mainPath stringByAppendingPathComponent:@"Dylibs/test_hook.dylib"];
    [self dlopenLoadDylibWithPath: dylibPath];
}

+(void)zzPrintDirInfo {
    // 获取Documents目录
    docPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject];
    
    // 获取tmp目录
    NSString *tmpPath = NSTemporaryDirectory();
    
    // 获取Library目录
    NSString *libPath = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) lastObject];
    
    // 获取Library/Caches目录
    NSString *cachePath = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) lastObject];
    
    // 获取Library/Preferences目录
    NSString *prePath = [NSSearchPathForDirectoriesInDomains(NSPreferencePanesDirectory, NSUserDomainMask, YES) lastObject];

    // 获取应用程序包的路径
    mainPath = [NSBundle mainBundle].resourcePath;

    NSLog(@"docPath: %@", docPath);
    NSLog(@"tmpPath: %@", tmpPath);
    NSLog(@"libPath: %@", libPath);
    NSLog(@"mainPath: %@", mainPath);
}

+(bool)dlopenLoadDylibWithPath:(NSString *)path {
    void *libHandle = NULL;
    libHandle = dlopen([path cStringUsingEncoding:NSUTF8StringEncoding], RTLD_NOW);
    if (libHandle == NULL) {
        char *error = dlerror();
        NSLog(@"dlopen error: %s", error);
    } else {
        NSLog(@"dlopen load framework success.");
    }
    return false;
}

+(bool)zzIsFileExist: (NSString *)filePath {
    NSFileManager *manager = [NSFileManager defaultManager];
    if (![manager fileExistsAtPath:filePath]) {
        NSLog(@"There isn't have the file");
        return YES;
    }
    NSFileManager *manager_dyld = [NSFileManager defaultManager];
    if (![manager_dyld fileExistsAtPath:@"/usr/lib/dyld"]) {
        NSLog(@"There isn't have dyld");
        return YES;
    }
    return FALSE;
}

@end

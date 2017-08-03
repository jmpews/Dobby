
extern "C" {
#include "hookzz.h"
}

#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/types.h>

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif

// static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
// static int fake_ptrace(int request, pid_t pid, caddr_t addr, int data) {
//   if (request == PT_DENY_ATTACH) {
//     NSLog(@"ByPass AntiDebug - ptrace");
//     return 0;
//   }
//   return orig_ptrace(request, pid, addr, data);
// }

// int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp,
//                    void *newp, size_t newlen);
// int fake_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
//                 void *newp, size_t newlen) {
//   struct kinfo_proc *info = NULL;
//   int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
//   if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
//     info = (struct kinfo_proc *)oldp;
//     info->kp_proc.p_flag &= ~(P_TRACED);
//   }
// }

#include "MachoMem.h"
void patch_svc_pre_call(struct RegState_ *rs) {
  int request = (int)(uint64_t)(rs->general.regs.x0);
  if (request == 31) {
  }
  *(unsigned long *)(&rs->general.regs.x0) = 10;
}
__attribute__((constructor)) void patch_svc_x80() {
  const section_64_info_t *sect64;
  zaddr svc_x80_addr;
  zaddr curr_addr, end_addr;
  uint32_t svc_x80_byte = 0xd4001001;
  MachoMem *mem = new MachoMem();
  mem->parse_macho();
  mem->parse_dyld();
  sect64 = mem->get_sect_by_name("__text");
  curr_addr = sect64->sect_addr;
  end_addr = curr_addr + sect64->sect_64->size;

  ZZInitialize();
  while (curr_addr < end_addr) {
    svc_x80_addr = mem->macho_search_data(
        sect64->sect_addr, sect64->sect_addr + sect64->sect_64->size,
        (const zbyte *)&svc_x80_byte, 4);
    if (svc_x80_addr) {
      ZZBuildHook((void *)svc_x80_addr, NULL, NULL,
                  (zpointer)patch_svc_pre_call, NULL);
      ZZEnableHook((void *)svc_x80_addr);
      curr_addr = svc_x80_addr + 4;
    } else {
      break;
    }
  }
}

// void AntiDebugBypass() {}


#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

extern "C" {
    #include "hookzz.h"
}

@interface SpiderZz: NSObject

@end

@implementation SpiderZz

NSString *docPath;
NSString *mainPath;

+ (void)load
{
    [self zzPrintDirInfo];
    NSString *dylibPath = [mainPath stringByAppendingPathComponent:@"Dylibs/test_hook.dylib"];
    // [self dlopenLoadDylibWithPath: dylibPath];
    [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(struct RegState_ *rs) {
    printf("call -[ViewController %s]", (zpointer) (rs->general.regs.x1));
}

+(void)zzMethodSwizzlingHook {
    Class hookClass = objc_getClass("UIViewController");
    SEL oriSEL = @selector(viewWillAppear:);
    Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
    IMP oriImp = method_getImplementation(oriMethod);

    ZZInitialize();
    ZZBuildHook((void *)oriImp, NULL, NULL,
                (zpointer) objcMethod_pre_call, NULL);
    ZZEnableHook((void *) oriImp);
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
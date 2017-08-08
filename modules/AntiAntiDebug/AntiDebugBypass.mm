
extern "C" {
#include "hookzz.h"
}

#import <Foundation/Foundation.h>

#include <sys/sysctl.h>
#include <sys/types.h>

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif
#if !defined(SYS_ptrace)
#define SYS_ptrace 26
#endif
#if !defined(SYS_syscall)
#define SYS_syscall 0
#endif

// --- ptrace, sysctl, syscall bypass ---

// runtime to get symbol address, but must link with `
// -Wl,-undefined,dynamic_lookup` or you can use `dlopen` and `dlsym`
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int fake_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  if (request == PT_DENY_ATTACH) {
    NSLog(@"[AntiDebugBypass] catch 'ptrace(PT_DENY_ATTACH)' and bypass.");
    return 0;
  }
  return orig_ptrace(request, pid, addr, data);
}

int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                   void *newp, size_t newlen);
int fake_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                void *newp, size_t newlen) {
  struct kinfo_proc *info = NULL;
  int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
  if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
    info = (struct kinfo_proc *)oldp;
    info->kp_proc.p_flag &= ~(P_TRACED);
    NSLog(@"[AntiDebugBypass] catch 'sysctl' and bypass.");
  }
}

// ptrace(int request, pid_t pid, caddr_t addr, int data);
int (*orig_syscall)(int number, ...);
int fake_syscall(int number, ...) {
  int request;
  pid_t pid;
  caddr_t addr;
  int data;

  if (number == SYS_ptrace) {
    va_list args;
    va_start(args, number);
    request = va_arg(args, int);
    pid = va_arg(args, pid_t);
    addr = va_arg(args, caddr_t);
    data = va_arg(args, int);
    va_end(args);
    if (request == PT_DENY_ATTACH) {
      NSLog(@"[AntiDebugBypass] catch 'syscall(SYS_ptrace, PT_DENY_ATTACH, 0, "
            @"0, 0)' and bypass.");
      return 0;
    }
  }
  int x = orig_syscall(number, request, pid, addr, data);
  return x;
}

__attribute__((constructor)) void patch_ptrace_sysctl_syscall() {

  zpointer ptrace_ptr = (void *)ptrace;
  ZZBuildHook((void *)ptrace_ptr, (void *)fake_ptrace, (void **)&orig_ptrace,
              NULL, NULL);
  ZZEnableHook((void *)ptrace_ptr);

  zpointer sysctl_ptr = (void *)sysctl;
  ZZBuildHook((void *)sysctl_ptr, (void *)fake_sysctl, (void **)&orig_sysctl,
              NULL, NULL);
  ZZEnableHook((void *)sysctl_ptr);

  // zpointer syscall_ptr = (void *)syscall;
  // ZZBuildHook((void *)syscall_ptr, (void *)fake_syscall, (void
  // **)&orig_syscall,
  //             NULL, NULL);
  // ZZEnableHook((void *)syscall_ptr);
}
// --- end --

// --- syscall bypass use `pre_call`
void syscall_pre_call(struct RegState_ *rs) {
  int num_syscall;
  int request;
  zpointer sp;
  num_syscall = (int)(uint64_t)(rs->general.regs.x0);
  if (num_syscall == SYS_ptrace) {
    sp = (zpointer)(rs->sp);
    request = *(int *)sp;
    if (request == PT_DENY_ATTACH) {
      *(long *)sp = 10;
      NSLog(@"[AntiDebugBypass] catch 'syscall(SYS_ptrace, PT_DENY_ATTACH, 0, "
            @"0, 0)' and bypass.");
    }
  }
}
__attribute__((constructor)) void patch_syscall_by_pre_call() {
  zpointer syscall_ptr = (void *)syscall;
  ZZBuildHook((void *)syscall_ptr, NULL, NULL, (void *)syscall_pre_call, NULL);
  ZZEnableHook((void *)syscall_ptr);
}

// --- end ---

// --- svc #0x80 bypass ---

#include "MachoMem.h"
void patch_svc_pre_call(struct RegState_ *rs) {
  int num_syscall;
  int request;
  num_syscall = (int)(uint64_t)(rs->general.regs.x16);
  request = (int)(uint64_t)(rs->general.regs.x0);

  if (num_syscall == SYS_syscall) {
    int arg1 = (int)(uint64_t)(rs->general.regs.x1);
    if (request == SYS_ptrace && arg1 == PT_DENY_ATTACH) {
      *(unsigned long *)(&rs->general.regs.x1) = 10;
      NSLog(@"[AntiDebugBypass] catch 'SVC #0x80; syscall(ptrace)' and bypass");
    }
  } else if (num_syscall == SYS_ptrace) {
    request = (int)(uint64_t)(rs->general.regs.x0);
    if (request == PT_DENY_ATTACH) {
      *(unsigned long *)(&rs->general.regs.x1) = 10;
      NSLog(@"[AntiDebugBypass] catch 'SVC-0x80; ptrace' and bypass");
    }
  }
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
      NSLog(@"find svc #0x80 at %p with aslr (%p without aslr)",
            (void *)svc_x80_addr, (void *)(svc_x80_addr - mem->m_aslr_slide));
      ZZBuildHook((void *)svc_x80_addr, NULL, NULL,
                  (zpointer)patch_svc_pre_call, NULL);
      ZZEnableHook((void *)svc_x80_addr);
      curr_addr = svc_x80_addr + 4;
    } else {
      break;
    }
  }
}
// --- end ---

// void AntiDebugBypass() {}

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>

extern "C" {
#include "hookzz.h"
}

@interface SpiderZz : NSObject

@end

@implementation SpiderZz

NSString *docPath;
NSString *mainPath;

+ (void)load {
  [self zzPrintDirInfo];
  NSString *dylibPath =
      [mainPath stringByAppendingPathComponent:@"Dylibs/test_hook.dylib"];
  // [self dlopenLoadDylibWithPath: dylibPath];
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

  ZZInitialize();
  ZZBuildHook((void *)oriImp, NULL, NULL, (zpointer)objcMethod_pre_call, NULL);
  ZZEnableHook((void *)oriImp);
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

+ (bool)dlopenLoadDylibWithPath:(NSString *)path {
  void *libHandle = NULL;
  libHandle =
      dlopen([path cStringUsingEncoding:NSUTF8StringEncoding], RTLD_NOW);
  if (libHandle == NULL) {
    char *error = dlerror();
    NSLog(@"dlopen error: %s", error);
  } else {
    NSLog(@"dlopen load framework success.");
  }
  return false;
}

+ (bool)zzIsFileExist:(NSString *)filePath {
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

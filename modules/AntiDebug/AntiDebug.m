#include "AntiDebug.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>

// https://jaq.alibaba.com/blog.htm?id=53
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif
typedef int (*PTRACE_T)(int request, pid_t pid, caddr_t addr, int data);

// ------------------------------------------------------------------

static void AntiDebug_ptrace() {
  void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
  PTRACE_T ptrace_ptr = dlsym(handle, "ptrace");
  ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
}

// ------------------------------------------------------------------

static __attribute__((always_inline)) void AntiDebug_svc() {
#if 1
#ifdef __arm64__
  // syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0)
  __asm__("mov X0, #31\n"
          "mov X1, #0\n"
          "mov X2, #0\n"
          "mov X3, #0\n"
          "mov w16, #26\n"
          "svc #0x80");
#endif
#else
#ifdef __arm64__
  // syscall(SYS_syscall, SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0)
  __asm__("mov X0, #31\n"
          "mov X1, #26\n"
          "mov X2, #0\n"
          "mov X3, #0\n"
          "mov X4, #0\n"
          "mov w16, #0\n"
          "svc #0x80");
#endif
#endif
  return;
}

// ------------------------------------------------------------------

#include <sys/syscall.h>
#if !defined(SYS_ptrace)
#define SYS_ptrace 26
#endif
void AntiDebug_syscall() { syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0); }

// ------------------------------------------------------------------

#include <sys/sysctl.h>
#include <unistd.h>
static int DetectDebug_sysctl() __attribute__((always_inline));
int DetectDebug_sysctl() {
  size_t size = sizeof(struct kinfo_proc);
  struct kinfo_proc info;
  int ret, name[4];

  memset(&info, 0, sizeof(struct kinfo_proc));

  name[0] = CTL_KERN;
  name[1] = KERN_PROC;
  name[2] = KERN_PROC_PID;
  name[3] = getpid();

  if ((ret = (sysctl(name, 4, &info, &size, NULL, 0)))) {
    return ret; // sysctl() failed for some reason
  }
  return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

void AntiDebug_sysctl() {
  if (DetectDebug_sysctl()) {
    exit(1);
  }
}

#include <unistd.h>
void AntiDebug_isatty() {
  if (isatty(1)) {
    exit(1);
  } else {
  }
}

#include <sys/ioctl.h>
void AntiDebug_ioctl() {
  if (!ioctl(1, TIOCGWINSZ)) {
    exit(1);
  } else {
  }
}

// uint32_t _dyld_image_count(void);
// void _dyld_register_func_for_add_image(
//     void (*func)(const struct mach_header *mh, intptr_t vmaddr_slide));
// struct mach_header *_dyld_get_image_header(uint32_t image_index);
// char *_dyld_get_image_name(uint32_t image_index);

#include <mach-o/dyld.h>
#import <objc/runtime.h>
void DetectLoadDylibs() {
  // struct mach_header *_dyld_get_image_header(uint32_t image_index);
  const struct mach_header *header;
  zpointer load_cmd_addr;
  struct load_command *load_cmd;
  struct dylib_command *dy_cmd;
  struct dylib lib;
  const char *dylib_name;

  header = _dyld_get_image_header(0);

  bool is64bit = header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64;
  if (is64bit) {
    load_cmd_addr = (zpointer)(header + sizeof(struct mach_header_64));
    for (zsize i = 0; i < header->ncmds; i++) {
      load_cmd = (struct load_command *)load_cmd_addr;
      if (load_cmd->cmd == LC_ID_DYLIB) {
        dy_cmd = (struct dylib_command *)load_cmd_addr;
        lib = dy_cmd->dylib;
        dylib_name = (char *)(load_cmd_addr + lib.name.offset);
      }
    }
  }
}

void DetectImageList() {
  zsize count = _dyld_image_count();
  const char *dyld_name;
  for (zsize i = 0; i < count; i++) {
    dyld_name = _dyld_get_image_name(i);
  }
}
void DetectFileList() {
  if ([[NSFileManager defaultManager]
          fileExistsAtPath:@"/Applications/Cydia.app"]) {
  }
}
void AntiCracker() {
  // AntiDebug_ptrace();

  AntiDebug_svc();
  // AntiDebug_syscall();
  // AntiDebug_sysctl();

  // DetectFileList();
  // DetectImageList();
  // DetectLoadDylibs();
}
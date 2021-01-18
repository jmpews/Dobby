#include "dobby_internal.h"

#include <mach/mach.h>

#include "SupervisorCallMonitor/supervisor_call_monitor.h"
#include "external_helper/async_logger.h"

#include "XnuInternal/syscalls.c"

static const char *syscall_num_to_str(int num) {
  return syscallnames[num];
}

static addr_t getCallFirstArg(RegisterContext *reg_ctx) {
  addr_t result;
#if defined(_M_X64) || defined(__x86_64__)
#if defined(_WIN32)
  result = reg_ctx->general.regs.rcx;
#else
  result = reg_ctx->general.regs.rdi;
#endif
#elif defined(__arm64__) || defined(__aarch64__)
  result = reg_ctx->general.regs.x0;
#elif defined(__arm__)
  result = reg_ctx->general.regs.r0;
#else
#error "Not Support Architecture."
#endif
  return result;
}

extern const char *mach_syscall_num_to_str(int num);

extern char *mach_msg_to_str(mach_msg_header_t *msg);

static void syscall_log_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  char buffer[256] = {0};
  int  syscall_rum = reg_ctx->general.regs.x16;
  if (syscall_rum == 0) {
    syscall_rum = (int)getCallFirstArg(reg_ctx);
    sprintf(buffer, "[syscall svc-%d] %s\n", syscall_rum, syscall_num_to_str(syscall_rum));

  } else if (syscall_rum > 0) {
    sprintf(buffer, "[svc-%d] %s\n", syscall_rum, syscall_num_to_str(syscall_rum));
  }
  async_logger_print(buffer);
}

void supervisor_call_monitor_register_syscall_call_log_handler() {
  supervisor_call_monitor_register_handler(syscall_log_handler);
}
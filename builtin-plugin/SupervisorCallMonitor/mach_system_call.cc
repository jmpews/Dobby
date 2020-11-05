#include "dobby_internal.h"

#include "MachUtility.h"

#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <unistd.h>
#include <stdlib.h>

#include <iostream>

#include "async_logger.h"

extern char *mach_msg_to_str(mach_msg_header_t *msg);

typeof(mach_msg) *orig_mach_msg = NULL;

int i = 0;

mach_msg_return_t fake_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size,
                                mach_msg_size_t rcv_size, mach_port_name_t rcv_name, mach_msg_timeout_t timeout,
                                mach_port_name_t notify) {
  char buffer[256] = {0};
  char *mach_msg_name = mach_msg_to_str(msg);
  if(mach_msg_name) {
    sprintf(buffer, "[%d][mach_msg] %s\n",i++, mach_msg_name);
    async_logger_print(buffer);
  }
#if 0
  {
    write(STDOUT_FILENO, buffer, strlen(buffer) + 1);
  }
#endif
  return orig_mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify);
}

void mach_system_call_monitor() {
  void *mach_msg_ptr = (void *)DobbySymbolResolver(NULL, "mach_msg");
  log_set_level(1);
  DobbyHook(mach_msg_ptr, (void *)fake_mach_msg, (void **)&orig_mach_msg);
}

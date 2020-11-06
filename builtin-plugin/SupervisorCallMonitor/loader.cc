//
// Created by jmpews on 2020/11/5.
//

#include "dobby_internal.h"

#include <unistd.h>
#include <stdlib.h>

#include <sys/syscall.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "async_logger.h"

#include "XnuInternal/syscalls.c"
#include "XnuInternal/syscall_sw.c"

#include "XnuInternal/mach/clock_priv.h"
#include "XnuInternal/mach/clock_reply.h"
#include "XnuInternal/mach/clock.h"
#include "XnuInternal/mach/exc.h"
#include "XnuInternal/mach/host_priv.h"
#include "XnuInternal/mach/host_security.h"
#include "XnuInternal/mach/lock_set.h"
#include "XnuInternal/mach/mach_host.h"
#include "XnuInternal/mach/mach_port.h"
#include "XnuInternal/mach/mach_vm.h"
#include "XnuInternal/mach/mach_voucher.h"
#include "XnuInternal/mach/memory_entry.h"
#include "XnuInternal/mach/processor_set.h"
#include "XnuInternal/mach/processor.h"
#include "XnuInternal/mach/task.h"
#include "XnuInternal/mach/thread_act.h"
#include "XnuInternal/mach/vm_map.h"

typedef struct {
  char *mach_msg_name;
  int   mach_msg_id;
} mach_msg_entry_t;

// clang-format off
mach_msg_entry_t mach_msg_array[] = {
    subsystem_to_name_map_clock_priv,
    subsystem_to_name_map_clock_reply,
    subsystem_to_name_map_clock,
    subsystem_to_name_map_exc,
    subsystem_to_name_map_host_priv,
    subsystem_to_name_map_host_security,
    subsystem_to_name_map_lock_set,
    subsystem_to_name_map_mach_host,
    subsystem_to_name_map_mach_port,
    subsystem_to_name_map_mach_vm,
    subsystem_to_name_map_mach_voucher,
    subsystem_to_name_map_memory_entry,
    subsystem_to_name_map_processor_set,
    subsystem_to_name_map_processor,
    subsystem_to_name_map_task,
    subsystem_to_name_map_thread_act,
    subsystem_to_name_map_vm_map,
};
// clang-format on

#define PRIME_NUMBER 8387
char *     mach_msg_name_table[PRIME_NUMBER] = {0};
static int hash_mach_msg_num_to_ndx(int mach_msg_num) {
  return mach_msg_num % PRIME_NUMBER;
}
static void mach_msg_id_hash_table_init() {
  static bool initialized = false;
  if (initialized == true) {
    return;
  }
  initialized = true;

  int count = sizeof(mach_msg_array) / sizeof(mach_msg_array[0]);
  for (size_t i = 0; i < count; i++) {
    mach_msg_entry_t entry   = mach_msg_array[i];
    int              ndx     = hash_mach_msg_num_to_ndx(entry.mach_msg_id);
    mach_msg_name_table[ndx] = entry.mach_msg_name;
  }
}

const char *syscall_num_to_str(int num) {
  return syscallnames[num];
}

const char *mach_syscall_num_to_str(int num) {
  return mach_syscall_name_table[0 - num];
}

char *mach_msg_id_to_str(int msgh_id) {
  int ndx = hash_mach_msg_num_to_ndx(msgh_id);
  return mach_msg_name_table[ndx];
}

char *mach_msg_to_str(mach_msg_header_t *msg) {
  static mach_port_t self_port = MACH_PORT_NULL;

  if (self_port == MACH_PORT_NULL) {
    self_port = mach_task_self();
  }

  if (msg->msgh_remote_port == self_port) {
    return mach_msg_id_to_str(msg->msgh_id);
  }
  return NULL;
}

extern void system_call_monitor();

extern void mach_system_call_monitor();

__attribute__((constructor)) static void ctor() {
  log_set_level(1);
  log_switch_to_syslog();

  // create logger file
  char logger_path[1024] = {0};
  sprintf(logger_path, "%s%s", getenv("HOME"), "/Documents/svc_monitor.txt");
  LOG(1, "%s", logger_path);
  async_logger_init(logger_path);

  mach_msg_id_hash_table_init();
  
  dobby_enable_near_branch_trampoline();

  system_call_monitor();

  mach_system_call_monitor();
}

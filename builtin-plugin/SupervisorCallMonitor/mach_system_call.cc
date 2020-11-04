#include "dobby_internal.h"

#include "MachUtility.h"

#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <unistd.h>
#include <stdlib.h>

#include "XnuInternal/syscall_sw.c"

#include <mach/mach.h>

typedef struct {
  char *mach_msg_name;
  int   mach_msg_id;
} mach_msg_entry_t;

// clang-format off
mach_msg_entry_t mach_msg_array[] = {
  subsystem_to_name_map_clock_priv
  subsystem_to_name_map_clock_reply
  subsystem_to_name_map_clock
  subsystem_to_name_map_exc
  subsystem_to_name_map_host_priv
  subsystem_to_name_map_host_security
  subsystem_to_name_map_lock_set
  subsystem_to_name_map_mach_host
  subsystem_to_name_map_mach_port
  subsystem_to_name_map_mach_vm
  subsystem_to_name_map_mach_voucher
  subsystem_to_name_map_memory_entry
  subsystem_to_name_map_processor_set
  subsystem_to_name_map_processor
  subsystem_to_name_map_task
  subsystem_to_name_map_thread_act
  subsystem_to_name_map_vm_map
};
// clang-format on

#define PRIME_NUMBER 8387
char       mach_msg_name_table[PRIME_NUMBER] = {0};
static int hash_mach_msg_num_to_ndx(int mach_msg_num) {
  return mach_msg_num % PRIME_NUMBER;
}
static void init_hash_table() {
  static bool initialized = false;
  if (initialized == true) {
    return;
  }
  initialized = true;

  int count = sizeof(mach_msg_array) / sizeof(mach_msg_array[0]);
  for (size_t i = 0; i < count; i++) {
    mach_msg_entry_t entry   = mach_msg_array[i];
    int              ndx     = hash_mach_msg_num_to_ndx(entry.mach_msg_num);
    mach_msg_name_table[ndx] = entry.mach_msg_name;
  }
}

typeof(mach_msg) *original_mach_msg = NULL;

mach_msg_return_t fake_mach_msg(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size,
                                mach_msg_size_t rcv_size, mach_port_name_t rcv_name, mach_msg_timeout_t timeout,
                                mach_port_name_t notify) {
  char *mach_msg_name = NULL;
  int   ndx           = hash_mach_msg_num_to_ndx(msg->msgh_id);
  mach_msg_name       = mach_msg_name_table[ndx];
  {
    char buffer[256] = {0};
    sprintf(buffer, "call %s\n", mach_msg_name);
    write(STDOUT_FILENO, buffer, strlen(buffer) + 1);
  }
  return mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify);
}

#if 1
typedef int32_t                          arm64_instr_t;
__attribute__((constructor)) static void ctor() {
  void *mach_msg_ptr = (void *)DobbySymbolResolver(NULL, "mach_msg");
  DobbyHook(mach_msg_ptr, fake_mach_msg, &original_mach_msg);
}
#endif

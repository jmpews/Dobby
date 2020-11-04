#include "dobby_internal.h"

#include "MachUtility.h"

#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <unistd.h>
#include <stdlib.h>

#include "XnuInternal/syscalls.c"

void common_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  //  if((int64_t)reg_ctx->general.regs.x16 < 0)
  //    printf("-num: %ld", reg_ctx->general.regs.x16);
  //  else
  char buffer[256] = {0};
  int  syscall_rum = reg_ctx->general.regs.x16;
  sprintf(buffer, "call %s\n", syscallnames[syscall_rum]);
  write(STDOUT_FILENO, buffer, strlen(buffer) + 1);
}

#if 1
typedef int32_t                          arm64_instr_t;
__attribute__((constructor)) static void ctor() {
  auto   libsystem_c        = ProcessRuntimeUtility::GetProcessModule("libsystem_kernel.dylib");
  addr_t libsystem_c_header = (addr_t)libsystem_c.load_address;
  auto   text_section =
      mach_kit::macho_get_section_by_name_64((struct mach_header_64 *)libsystem_c_header, "__TEXT", "__text");

  addr_t shared_cache_load_addr = (addr_t)mach_kit::macho_get_shared_cache();
  addr_t insn_addr              = shared_cache_load_addr + (addr_t)text_section->offset;
  addr_t insn_addr_end          = insn_addr + text_section->size;

  log_set_level(1);
  addr_t write_svc_addr = (addr_t)DobbySymbolResolver("libsystem_kernel.dylib", "write");
  write_svc_addr += 4;
  for (insn_addr; insn_addr < insn_addr_end; insn_addr += sizeof(arm64_instr_t)) {
    if (*(arm64_instr_t *)insn_addr == 0xd4001001) {
      dobby_enable_near_branch_trampoline();
      if (insn_addr == write_svc_addr)
        continue;
      DobbyInstrument((void *)insn_addr, common_handler);
      LOG(1, "instrument svc at %p", insn_addr);
    }
  }
}
#endif

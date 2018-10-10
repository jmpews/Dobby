#ifndef platforms_arch_arm_writer_arm_h
#define platforms_arch_arm_writer_arm_h

#include "instruction.h"
#include "register-arm.h"

#include "std_kit/std_buffer_array.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_list.h"

typedef struct _address_stub_t {
  int ldr_inst_index;
  uintptr_t address;
} ldr_address_stub_t;

typedef struct _ARMAssemblerWriter {
  void *pc;
  void *buffer;

  list_t *instCTXs;
  buffer_array_t *inst_bytes;
  list_t *ldr_address_stubs;
} ARMAssemblerWriter;

#define arm_assembly_writer_cclass(member) cclass(arm_assembly_writer, member)
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

ARMAssemblyWriter *arm_assembly_writer_cclass(new)(void *pc);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
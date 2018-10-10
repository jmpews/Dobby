#ifndef platforms_arch_arm64_reader_arm64_h
#define platforms_arch_arm64_reader_arm64_h

#include "ARM64AssemblyCore.h"
#include "core.h"
#include "instruction.h"

#include "std_kit/std_kit.h"

typedef struct _ARM64AssemblyReader {
  void *pc;
  void *buffer;
  list_t *instCTXs;
  buffer_array_t *inst_bytes;
} ARM64AssemblyReader;

#define arm64_assembly_reader_cclass(member) cclass(arm64_assembly_reader, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
ARM64AssemblyReader *arm64_assembly_reader_cclass(new)(void *address, void *pc);

void arm64_assembly_reader_cclass(reset)(ARM64AssemblyReader *self, void *address, void *pc);

ARM64InstructionCTX *arm64_assembly_reader_cclass(read_inst)(ARM64AssemblyReader *self);
#ifdef __cplusplus
}
#endif //__cplusplus

#endif
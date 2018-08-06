#ifndef platforms_arch_arm_relocator_thumb_h
#define platforms_arch_arm_relocator_thumb_h

#include "instruction.h"
#include "reader-thumb.h"
#include "register-arm.h"
#include "writer-thumb.h"

#include "std_kit/std_buffer_array.h"
#include "std_kit/std_kit.h"
#include "std_kit/std_list.h"

typedef struct _io_index_t {
    int input_index;
    int output_index;
} io_index_t;

typedef struct _ThumbRelocator {
    ThumbAssemblyReader *input;
    ThumbAssemblyWriter *output;
    list_t *literal_instCTXs;
    list_t *io_indexs;
} ThumbRelocator;

#define thumb_assembly_relocator_cclass(member) cclass(thumb_relocator, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

ThumbRelocator *thumb_assembly_relocator_cclass(new)(ThumbAssemblyReader *input, ThumbAssemblyWriter *output);

void thumb_assembly_relocator_cclass(reset)(ThumbRelocator *self, ThumbAssemblyReader *input,
                                            ThumbAssemblyWriter *output);

void thumb_assembly_relocator_cclass(try_relocate)(void *address, int bytes_min, int *bytes_max);

void thumb_assembly_relocator_cclass(relocate_to)(ThumbRelocator *self, void *target_address);

void thumb_assembly_relocator_cclass(double_write)(ThumbRelocator *self, void *target_address);

void thumb_assembly_relocator_cclass(register_literal_instCTX)(ThumbRelocator *self, ThumbInstructionCTX *instCTX);

void thumb_assembly_relocator_cclass(relocate_write)(ThumbRelocator *self);

void thumb_assembly_relocator_cclass(relocate_write_all)(ThumbRelocator *self);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif
#include <assert.h>
#include <stdio.h>

// fake the not found function.
#ifdef __cplusplus
extern "C" {
#endif //__cplusplus
void closure_bridge_template();
void closure_bridge_trampoline_template();
#ifdef __cplusplus
}
#endif //__cplusplus
void closure_bridge_template() {}
void closure_bridge_trampoline_template() {}

#include "core.h"
#include "platforms/arch-arm64/relocator-arm64.h"
// mov x0, x0
// ldr x0, #0x10
// b #0x20
// cbz x0, #0x20
__attribute__((aligned(4))) uint32_t test_func[4]               = {0xAA0003E0, 0x58000080, 0x14000008, 0xB4000100};
__attribute__((aligned(4))) uint32_t relocated_func[32]         = {0};
__attribute__((aligned(4))) uint32_t correct_relocated_func[32] = {0};

// clang-format off
__attribute__((constructor)) void build_correct_relocated_func() {
/*
    origin:
        0x1000: mov x0, x0
    relocated:
        0x2000: mov x0, x0
*/
    correct_relocated_func[0] = 0xAA0003E0;

/*
    origin:
        0x1004: ldr x0, 0x10
    relocated:
        0x2004: ldr x0, #0x8
        0x2008: b #0xc
        0x200c: .long #0x1014
        0x2010: .long #0x0
        0x2014: ldr x0, [x0, #0x0]
*/
    correct_relocated_func[1] = 0x58000040;
    correct_relocated_func[2] = 0x14000003;
    *(uintptr_t *)&correct_relocated_func[3] = (uintptr_t)test_func + 4 + 0x10;
    correct_relocated_func[5] = 0xF9400000;

/*
    origin:
        0x1008: b #0x20
    relocated:
        0x2018: ldr x17, #0x8
        0x201c: br x17
        0x2020: .long #0x1028
        0x2024: .long #0x0
*/
    correct_relocated_func[6] = 0x58000051;
    correct_relocated_func[7] = 0xD61F0220;
    *(uintptr_t *)&correct_relocated_func[8] = (uintptr_t)test_func + 8 + 0x20;

/*
    origin:
        0x100c: cbz x0, #0x20
    relocated:
        0x2028: cbz x0, #0x8
        0x202c: b #0x14
        0x2030: ldr x17, #0x8
        0x2034: br x17
        0x2038: .long #0x102c
        0x203c: .long #0x0
*/
    correct_relocated_func[10] = 0xB4000040;
    correct_relocated_func[11] = 0x14000005;
    correct_relocated_func[12] = 0x58000051;
    correct_relocated_func[13] = 0xD61F0220;
    *(uintptr_t *)&correct_relocated_func[14] = (uintptr_t)test_func + 0xc + 0x20;
    return;
}
// clang-format on

int get_input_relocate_ouput_count(ARM64Relocator *relocator, int i) {
    io_index_t *io_index = (io_index_t *)(list_at(relocator->io_indexs, i)->val);
    if (i == relocator->io_indexs->len - 1) {
        return relocator->output->instCTXs->len - io_index->output_index;
    } else {
        io_index_t *io_index_next = (io_index_t *)(list_at(relocator->io_indexs, i + 1)->val);
        return io_index_next->output_index - io_index->output_index;
    }
}

#define ARM64_FULL_REDIRECT_SIZE 16

int main(int argc, char *argv[]) {
    ARM64AssemblyReader *reader_arm64;
    ARM64AssemblyWriter *writer_arm64;
    ARM64Relocator *relocator_arm64;
    reader_arm64    = arm64_assembly_reader_cclass(new)(test_func, test_func);
    writer_arm64    = arm64_assembly_writer_cclass(new)(0);
    relocator_arm64 = arm64_assembly_relocator_cclass(new)(reader_arm64, writer_arm64);

    int limit_relocate_inst_size = 0;
    arm64_assembly_relocator_cclass(try_relocate)(test_func, ARM64_FULL_REDIRECT_SIZE, &limit_relocate_inst_size);
    printf(">>> limit_relocate_inst_size: %d\n", limit_relocate_inst_size);

    // relocate `mov x0, x0`
    arm64_assembly_reader_cclass(read_inst)(reader_arm64);
    arm64_assembly_relocator_cclass(relocate_write)(relocator_arm64);
    printf("Relocate INFO:\n");
    int count            = get_input_relocate_ouput_count(relocator_arm64, 0);
    io_index_t *io_index = (io_index_t *)(list_at(relocator_arm64->io_indexs, 0)->val);
    assert(count == 1);
    for (int i = io_index->output_index; i < count + io_index->output_index; i++) {
        ARM64InstructionCTX *instCTX = (ARM64InstructionCTX *)(list_at(relocator_arm64->output->instCTXs, i)->val);
        assert(instCTX->bytes == correct_relocated_func[i]);
        // printf("0x%02x 0x%02x 0x%02x 0x%02x ", (uint8_t)instCTX->bytes, (uint8_t)(instCTX->bytes >> 8), (uint8_t)(instCTX->bytes >> 16), (uint8_t)(instCTX->bytes >> 24));
    }
    // relocate `ldr x0, #0x10`
    arm64_assembly_reader_cclass(read_inst)(reader_arm64);
    arm64_assembly_relocator_cclass(relocate_write)(relocator_arm64);
    count    = get_input_relocate_ouput_count(relocator_arm64, 1);
    io_index = (io_index_t *)(list_at(relocator_arm64->io_indexs, 1)->val);
    assert(count == 5);
    for (int i = io_index->output_index; i < count + io_index->output_index; i++) {
        ARM64InstructionCTX *instCTX = (ARM64InstructionCTX *)(list_at(relocator_arm64->output->instCTXs, i)->val);
        assert(instCTX->bytes == correct_relocated_func[i]);
        // printf("0x%02x 0x%02x 0x%02x 0x%02x ", (uint8_t)instCTX->bytes, (uint8_t)(instCTX->bytes >> 8), (uint8_t)(instCTX->bytes >> 16), (uint8_t)(instCTX->bytes >> 24));
    }

    // relocate `b #0x20`
    arm64_assembly_reader_cclass(read_inst)(reader_arm64);
    arm64_assembly_relocator_cclass(relocate_write)(relocator_arm64);
    count    = get_input_relocate_ouput_count(relocator_arm64, 2);
    io_index = (io_index_t *)(list_at(relocator_arm64->io_indexs, 2)->val);
    assert(count == 4);
    for (int i = io_index->output_index; i < count + io_index->output_index; i++) {
        ARM64InstructionCTX *instCTX = (ARM64InstructionCTX *)(list_at(relocator_arm64->output->instCTXs, i)->val);
        assert(instCTX->bytes == correct_relocated_func[i]);
        // printf("0x%02x 0x%02x 0x%02x 0x%02x ", (uint8_t)instCTX->bytes, (uint8_t)(instCTX->bytes >> 8), (uint8_t)(instCTX->bytes >> 16), (uint8_t)(instCTX->bytes >> 24));
    }

    // relocate `b #0x20`
    arm64_assembly_reader_cclass(read_inst)(reader_arm64);
    arm64_assembly_relocator_cclass(relocate_write)(relocator_arm64);
    count    = get_input_relocate_ouput_count(relocator_arm64, 3);
    io_index = (io_index_t *)(list_at(relocator_arm64->io_indexs, 3)->val);
    assert(count == 6);
    for (int i = io_index->output_index; i < count + io_index->output_index; i++) {
        ARM64InstructionCTX *instCTX = (ARM64InstructionCTX *)(list_at(relocator_arm64->output->instCTXs, i)->val);
        assert(instCTX->bytes == correct_relocated_func[i]);
        // printf("0x%02x 0x%02x 0x%02x 0x%02x ", (uint8_t)instCTX->bytes, (uint8_t)(instCTX->bytes >> 8), (uint8_t)(instCTX->bytes >> 16), (uint8_t)(instCTX->bytes >> 24));
    }

    return 0;
}
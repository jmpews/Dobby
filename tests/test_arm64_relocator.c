/*
export HookZzSrc=/Users/jmpews/project/HookZz/src
clang -I$HookZzSrc test_arm64_relocator.c \
$HookZzSrc/platforms/arch-arm64/ARM64AssemblyCore.c \
$HookZzSrc/platforms/arch-arm64/instructions.c \
$HookZzSrc/platforms/arch-arm64/reader-arm64.c \
$HookZzSrc/platforms/arch-arm64/relocator-arm64.c \
$HookZzSrc/platforms/arch-arm64/writer-arm64.c \
-o test_arm64_relocator
*/
#include "hookzz.h"
#include "macros.h"
#include "platforms/arch-arm64/relocator-arm64.h"

uint32_t ldr_x0_0x0  = 0x58000000;
uint32_t ldr_x0_0x32 = 0x0;

uint32_t b_0x0  = 0x0;
uint32_t b_0x32 = 0x0;

uint32_t bl_0x0  = 0x0;
uint32_t bl_0x32 = 0x0;

uint32_t cbz_x0_0x0  = 0x0;
uint32_t cbz_x0_0x32 = 0x0;

uint32_t test_insns[] = {
    0x0, 0x0,
};

void check() {
    ARM64Relocator arm64_relocator;
    ARM64AssemblyReader arm64_reader;
    ARM64AssemblyrWriter arm64_writer;
    char code_buffer[256] = {0};

    arm64_reader_reset(&arm64_reader, &ldr_x0_0x0);
    arm64_reader.start_pc = 0x1000;
    arm64_writer_reset(&arm64_writer, ALIGN_CEIL(code_buffer, 4), 0);
    arm64_writer.start_pc = 0x4000;
    arm64_relocator_reset(&arm64_relocator, &arm64_reader, &arm64_writer);

    arm64_relocator_read_one(&arm64_relocator, NULL);
    arm64_relocator_write_one(&arm64_relocator);

    printf("relocate: %x", arm64_reader.insnCTXs[0]->insn);
    for (size_t i = 0; i < arm64_relocator.relocated_insnCTXs_count; i++) {
        printf("\t%x\n", arm64_writer.insnCTXs[i]->insn);
    }
}

int main(int argc, char const *argv[]) {
    check();
    return 0;
}

#include "hookzz.h"
#include <stdio.h>
#include <unistd.h>

static void thumb_insn_need_fix() {
    __asm__ volatile(".code 16\n"

                     "add r0, pc\n"

                     "ldr r0, [pc, #8]\n"
                     "ldr.W r0, [pc, #8]\n"

                     "adr r0, #8\n"
                     "adr.W r0, #8\n"
                     "adr.W r0, #-8\n"

                     "beq #8\n"
                     "b #8\n"
                     "beq.W #8\n"
                     "b.W #8\n"

                     "bl #8\n"
                     "blx #8\n"
                     "nop");
}

#include "platforms/backend-arm64/interceptor-arm64.h"
#include <stdlib.h>

#if 1
__attribute__((constructor)) void test_insn_fix_thumb() {

    InterceptorBackend *backend  = (InterceptorBackend *)malloc(sizeof(InterceptorBackend));
    char temp_code_slice_data[256] = {0};

    writer_init(&backend->writer, NULL);
    relocator_init(&backend->relocator, NULL, &backend->writer);
    zz_writer_init(&backend->writer, NULL);
    zz_relocator_init(&backend->relocator, NULL, &backend->writer);

    ZzThumbRelocator *relocator;
    ZzThumbWriter *writer;
    relocator = &backend->relocator;
    writer    = &backend->writer;

    zz_writer_reset(writer, temp_code_slice_data);

    zz_relocator_reset(relocator, ((zz_addr_t)thumb_insn_need_fix & ~(zz_addr_t)1), writer);
    zz_size_t tmp_relocator_insn_size = 0;

    do {
        zz_relocator_read_one(relocator, NULL);
        zz_relocator_write_one(relocator);
        tmp_relocator_insn_size = relocator->input_cur - relocator->input_start;
    } while (tmp_relocator_insn_size < 36);
}
#endif

#if 0
__attribute__((__naked__)) void arm_insn_need_fix() {
    __asm__ volatile(".arm\n"
                     "add r0, pc, r0\n"

                     "ldr r0, [pc, #8]\n"

                     "adr r0, #8\n"
                     "adr r0, #-8\n"

                     "beq #8\n"
                     "b #8\n"

                     "bl #8\n"
                     "blx #8\n"
                     "nop");
}

#include "platforms/backend-arm/interceptor-arm.h"
#include <stdlib.h>

__attribute__((constructor)) void test_insn_fix_arm() {

    InterceptorBackend *backend = (InterceptorBackend *)malloc(sizeof(InterceptorBackend));
    char temp_code_slice_data[256] = {0};

    writer_init(&backend->writer, NULL);
    relocator_init(&backend->relocator, NULL, &backend->writer);
    zz_writer_init(&backend->writer, NULL);
    zz_relocator_init(&backend->relocator, NULL, &backend->writer);

    ARMRelocator *relocator;
    ARMWriter *writer;
    relocator = &backend->relocator;
    writer = &backend->writer;

    writer_reset(writer, temp_code_slice_data);

    relocator_reset(relocator, ((zz_addr_t)arm_insn_need_fix & ~(zz_addr_t)1), writer);
    zz_size_t tmp_relocator_insn_size = 0;

    do {
        relocator_read_one(relocator, NULL);
        relocator_write_one(relocator);
        tmp_relocator_insn_size = relocator->input_cur - relocator->input_start;
    } while (tmp_relocator_insn_size < 36);
}
#endif
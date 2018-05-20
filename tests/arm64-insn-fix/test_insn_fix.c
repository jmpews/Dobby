#include "hookzz.h"
#include <stdio.h>
#include <unistd.h>

static void arm64_insn_need_fix() {
    __asm__ volatile("bl #40\n"
                     "nop");
}

#include "platforms/backend-arm64/interceptor-arm64.h"
#include <stdlib.h>

#if 1
__attribute__((constructor)) void test_insn_fix_arm64() {

    InterceptorBackend *backend  = (InterceptorBackend *)malloc(sizeof(InterceptorBackend));
    char temp_code_slice_data[256] = {0};

    zz_writer_init(&backend->writer, NULL);
    zz_relocator_init(&backend->relocator, NULL, &backend->writer);
    zz_writer_init(&backend->writer, NULL);
    zz_relocator_init(&backend->relocator, NULL, &backend->writer);

    ARM64Relocator *relocator;
    ARM64Writer *writer;
    relocator = &backend->relocator;
    writer    = &backend->writer;

    zz_writer_reset(writer, temp_code_slice_data);

    zz_relocator_reset(relocator, ((zz_addr_t)arm64_insn_need_fix & ~(zz_addr_t)1), writer);
    zz_size_t tmp_relocator_insn_size = 0;

    do {
        zz_relocator_read_one(relocator, NULL);
        zz_relocator_write_one(relocator);
        tmp_relocator_insn_size = relocator->input_cur - relocator->input_start;
    } while (tmp_relocator_insn_size < 36);
}
#endif

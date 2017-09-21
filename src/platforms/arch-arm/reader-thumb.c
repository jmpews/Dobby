//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#include "reader-thumb.h"

static csh handle;

void zz_thumb_reader_capstone_init(void) {
    cs_err err = 0;

    err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle);
    if (err) {
        Xerror("Failed on cs_open() with error returned: %u\n", err);
        exit(-1);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

cs_insn *zz_thumb_reader_disassemble_at(zpointer address) {
    if (!handle)
        zz_thumb_reader_capstone_init();
    cs_insn *insn;
    size_t count;
    count = cs_disasm(handle, address, 16, (unsigned long)address, 0, &insn);
    if (!insn) {
#if defined(DEBUG_MODE)
        debug_break();
#endif
        Xerror("zz_thumb_reader_disassemble_at error at %p", (zpointer)address);
    }
    return insn;
}
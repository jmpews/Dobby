#include "instructions.h"
#include <string.h>

uint32_t get_insn_sub(uint32_t insn, int start, int length) { return (insn >> start) & ((1 << length) - 1); }

bool insn_equal(uint32_t insn, char *opstr) {
    uint32_t mask = 0, value = 0;
    zz_size_t length = strlen(opstr);
    int i, j;
    for (i = length - 1, j = 0; i >= 0 && j < length; i--, j++) {
        if (opstr[i] == 'x') {
            mask = mask | (0 << j);
        } else if (opstr[i] == '0') {
            mask = mask | (1 << j);
        } else if (opstr[i] == '1') {
            value = value | (1 << j);
            mask  = mask | (1 << j);
        }
    }
    return (insn & mask) == value;
}
#include "instructions.h"
#include <string.h>

zuint32 get_insn_sub(zuint32 insn, int start, int length) { return (insn >> start) & (1 << (length - 1)); }

zbool insn_equal(zuint32 insn, char *opstr) {
    zuint32 mask = 0, value = 0;
    zsize length = strlen(opstr);
    for (int i = length - 1; i >= 0; i--) {
        if (opstr[i] == 'x') {
            mask = mask | (0 << i);
        } else if (opstr[i] == '0') {
            mask = mask | (1 << i);
        } else if (opstr[i] == '1') {
            value = value | (1 << i);
            mask = mask | (1 << i);
        }
    }
    return (insn & mask) == value;
}
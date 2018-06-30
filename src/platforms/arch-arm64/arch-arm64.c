#include "hookzz.h"

void *get_next_hop_addr_PTR(RegState *rs) {
    void *next_hop_addr_PTR = (void *)&rs->general.regs.x15;
    return next_hop_addr_PTR;
}

void *get_ret_addr_PTR(RegState *rs) {
    void *ret_addr_PTR = (void *)&rs->lr;
    return ret_addr_PTR;
}
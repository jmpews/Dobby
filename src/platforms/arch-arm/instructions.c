#include "instructions.h"
#include <string.h>

static uint32_t get_insn_sub(uint32_t insn, int start, int length) {
  return (insn >> start) & ((1 << length) - 1);
}

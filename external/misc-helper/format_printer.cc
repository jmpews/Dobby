#include "format_printer.h"

void hexdump(const uint8_t *bytes, size_t len) {
  size_t ix;
  for (ix = 0; ix < len; ++ix) {
    if (ix != 0 && !(ix % 16))
      printf("\n");
    printf("%02X ", bytes[ix]);
  }
  printf("\n");
}


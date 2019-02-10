#include "stdcxx/LiteMemOpt.h"
#include "globals.h"

#include <stdlib.h>

void *memcpy(void *dest, const void *src, int len) {
  return memcpy(dest, src, len);
}

void *memset(void *dest, int ch, int count) {
  return memset(dest, ch, count);
}

void *LiteMemOpt::alloc(int size) {
  void *result = malloc(size);
  return result;
}

void LiteMemOpt::free(void *address, int size) {
  return ::free(address);
}

#include "stdcxx/LiteMemOpt.h"
#include "globals.h"

#if defined(KERNELMODE)

void LiteMemOpt::copy(void *dest, void *src, int length) {
  memcpy(dest, src, length);
  return;
}

void *LiteMemOpt::alloc(int size) {
  return 0;
}

void LiteMemOpt::free(void *address, int size) {
}

void LiteMemOpt::read(void *address, void *data, int length) {
  LiteMemOpt::copy(data, address, length);
  return;
}

void LiteMemOpt::write(void *address, void *data, int length) {
  LiteMemOpt::copy(address, data, length);
  return;
}

#else

void LiteMemOpt::copy(void *dest, void *src, int length) {
  memcpy(dest, src, length);
  return;
}

void *LiteMemOpt::alloc(int size) {
  void *result = malloc(size);
  return result;
}

void LiteMemOpt::free(void *address, int size) {
  return ::free(address);
}

#endif

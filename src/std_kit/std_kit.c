#include "std_kit.h"
void *safe_malloc(size_t size) {
  if (size <= 0) {
    ERROR_LOG("[!] malloc with size %ld", size);
    return NULL;
  }
  void *data = (void *)malloc(size);
  if (!data) {
    ERROR_LOG_STR("[!] malloc return NULL !!!");
    return data;
  }
  memset(data, 0, size);
  return data;
}

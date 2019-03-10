#include <hookzz.h>
#include <stdio.h>

FILE *(*orig_fopen)(const char *filename, const char *mode);
FILE *fake_fopen(const char *filename, const char *mode) {
  printf("fopen: %s\n", filename);
  return orig_fopen(filename, mode);
}

size_t (*orig_fread)(void *ptr, size_t size, size_t count, FILE *stream);
size_t fake_fread(void *ptr, size_t size, size_t count, FILE *stream) {
  printf("fread: %p\n", ptr);
  return orig_fread(ptr, size, count, stream);
}

int main(int argc, char const *argv[]) {

  ZzReplace((void *)fopen, (void *)fake_fopen, (void **)&orig_fopen);

  ZzReplace((void *)fread, (void *)fake_fread, (void **)&orig_fread);

  char buffer[64];
  FILE *fd = fopen("/test", "r");
  fread(buffer, 64, 1, fd);

  return 0;
}

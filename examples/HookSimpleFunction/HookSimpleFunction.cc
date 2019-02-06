#include <hookzz.h>
#include <stdio.h>

FILE *(*orig_fopen)(const char *filename, const char *mode);

FILE *fake_fopen(const char *filename, const char *mode) {
  printf("fopen: %s\n", filename);
  return orig_fopen(filename, mode);
}

int main(int argc, char const *argv[]) {

  ZzReplace((void *)fopen, (void *)fake_fopen, (void **)&orig_fopen);

  fopen("/test", "r");

  return 0;
}

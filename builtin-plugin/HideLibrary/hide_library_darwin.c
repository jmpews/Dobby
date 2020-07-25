#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <stdint.h>
#include <stdio.h>

#include <mach/mach.h>

#include <string.h>

#include "dobby_symbol_resolver.h"

#include "logging/logging.h"

void *(*removeImageFromAllImages)(const struct mach_header *mh) = NULL;

static void init_miss_symbol() {
  removeImageFromAllImages = DobbySymbolResolver("dyld", "__Z24removeImageFromAllImagesPK11mach_header");
}

int DobbyHideLibrary(const char *library_name) {
  if (removeImageFromAllImages == NULL) {
    init_miss_symbol();
    if (!removeImageFromAllImages)
      return -1;
  }

  int image_count = _dyld_image_count();
  for (size_t i = 0; i < image_count; i++) {
    const char *image_path = _dyld_get_image_name(i);
    char *image_name       = strrchr(image_path, '/');
    if (!image_name)
      image_name = (char *)image_path;

    if (strcmp(image_name, library_name) == 0) {
      removeImageFromAllImages(_dyld_get_image_header(i));
      LOG("remove %s library logically", library_name);
    }
  }
  return 0;
}

__attribute__((constructor)) static void ctor() {
  // DobbyHideLibrary("libdobby.dylib");
}
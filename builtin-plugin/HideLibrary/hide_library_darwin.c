#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <stdint.h>
#include <stdio.h>

#include <mach/mach.h>

#include <string.h>

#include "dobby.h"

#include "logging/logging.h"

static void *(*removeImageFromAllImages)(const struct mach_header *mh) = NULL;

int DobbyHideLibrary(const char *library_name) {
  if (removeImageFromAllImages == NULL) {
    removeImageFromAllImages = DobbySymbolResolver("dyld", "__Z24removeImageFromAllImagesPK11mach_header");
  }

  int image_count = _dyld_image_count();
  for (size_t i = 0; i < image_count; i++) {
    const char *image_path = _dyld_get_image_name(i);
    if(image_path == NULL)
      continue;;
    
    char *image_name       = strrchr(image_path, '/');
    
    if (!image_name)
      continue;
    
    // skip slash
    image_name += 1;

    if (strcmp(image_name, library_name) == 0) {
      removeImageFromAllImages(_dyld_get_image_header(i));
      LOG("remove %s library logically", library_name);
    }
  }
  return 0;
}

static bool is_removed_flag = false;
static void monitor_linker_load(const char *image_name, void *handle) {
  if (removeImageFromAllImages == NULL) {
    removeImageFromAllImages = DobbySymbolResolver("dyld", "__Z24removeImageFromAllImagesPK11mach_header");
  }
  
  LOG("load %s at %p", image_name, handle);
  if(strcmp(image_name, "Dobby") == 0) {
    removeImageFromAllImages(handle);
  }
  
  if(is_removed_flag == false) {
    DobbyHideLibrary("Dobby");
    DobbyHideLibrary("liblangid.dylib");
    is_removed_flag = true;
  }
}

#if defined(DOBBY_DEBUG)
__attribute__((constructor)) static void ctor() {
  dobby_register_image_load_callback(monitor_linker_load);
}
#endif

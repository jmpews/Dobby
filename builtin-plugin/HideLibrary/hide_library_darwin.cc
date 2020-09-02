#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <stdint.h>
#include <stdio.h>

#include <mach/mach.h>

#include <string.h>

#include <vector>

#include "dobby.h"

#include "logging/logging.h"

#include <mach-o/dyld_images.h>

typedef void ImageLoader;

typedef void ImageLoaderMachO;

static void *(*removeImageFromAllImages)(struct mach_header *mh) = NULL;

static char *(*ImageLoader__getShortName)(ImageLoader *loader) = NULL;

static struct mach_header *(*ImageLoaderMachO__machHeader)(ImageLoaderMachO *loader) = NULL;

static std::vector<ImageLoader *> *sAllImages = NULL;

std::vector<char *> *remove_image_array;

int DobbyHideLibrary(const char *library_name) {
  if (remove_image_array == NULL)
    remove_image_array = new std::vector<char *>();
  remove_image_array->push_back((char *)library_name);
}

int dobby_hide_library_internal(const char *library_name) {
  if (removeImageFromAllImages == NULL) {
    removeImageFromAllImages =
        (typeof(removeImageFromAllImages))DobbySymbolResolver("dyld", "__Z24removeImageFromAllImagesPK11mach_header");
  }

  if (ImageLoader__getShortName == NULL) {
    ImageLoader__getShortName =
        (typeof(ImageLoader__getShortName))DobbySymbolResolver("dyld", "__ZNK11ImageLoader12getShortNameEv");
  }

  if (ImageLoaderMachO__machHeader == NULL) {
    ImageLoaderMachO__machHeader =
        (typeof(ImageLoaderMachO__machHeader))DobbySymbolResolver("dyld", "__ZNK16ImageLoaderMachO10machHeaderEv");
  }

  if (sAllImages == NULL)
    sAllImages = (typeof(sAllImages))DobbySymbolResolver("dyld", "__ZN4dyldL10sAllImagesE");

  for (std::vector<ImageLoader *>::iterator it = sAllImages->begin(); it != sAllImages->end(); it++) {
    char *name = ImageLoader__getShortName(*it);
    DLOG("loader: %s", name);
    if (strcmp(name, library_name) == 0) {
      struct mach_header *header = ImageLoaderMachO__machHeader(*it);
      removeImageFromAllImages(header);
      sAllImages->erase(it);
      break;
    }
  }

  return 0;
}

static void common_handler(RegisterContext *reg_ctx, const HookEntryInfo *info) {
  for (auto name : *remove_image_array) {
    dobby_hide_library_internal(name);
  }
}

__attribute__((constructor)) static void ctor() {
  void *dyld__notifyMonitoringDyldMain = DobbySymbolResolver("dyld", "__ZN4dyldL24notifyMonitoringDyldMainEv");
  DobbyInstrument(dyld__notifyMonitoringDyldMain, common_handler);

#if defined(DOBBY_DEBUG) && 1
  DobbyHideLibrary("Dobby");
  DobbyHideLibrary("liblangid.dylib");
#endif
}

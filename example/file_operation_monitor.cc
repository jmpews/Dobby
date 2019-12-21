//
//  YourHackL1b.cpp
//  HookExample
//
//  Created by jmpews on 2019/3/25.
//  Copyright © 2019 jmpews. All rights reserved.
//

#include "YourHackL1b.hpp"

#include <stdlib.h> /* getenv */

#include <stdio.h>

#include <string.h>

#include <iostream>
#include <fstream>

#include <set>

#include <unordered_map>

std::unordered_map<FILE *, const char *> *TracedFileList;

FILE *(*orig_fopen)(const char *filename, const char *mode);
FILE *fake_fopen(const char *filename, const char *mode) {
  std::cout << "[-] trace file: " << filename << std::endl;
  FILE *result = NULL;
  result       = orig_fopen(filename, mode);
  TracedFileList->insert(std::make_pair(result, filename));
  return result;
}

const char *GetFileDescriptorTraced(FILE *file) {
  std::unordered_map<FILE *, const char *>::iterator it;
  it = TracedFileList->find(file);
  if (it != TracedFileList->end())
    return it->second;
  return NULL;
}

size_t (*orig_fread)(void *ptr, size_t size, size_t count, FILE *stream);
size_t fake_fread(void *ptr, size_t size, size_t count, FILE *stream) {
  const char *file_name = GetFileDescriptorTraced(stream);
  if (file_name) {
    printf("[-] fread %s\n    to %p\n", file_name, ptr);
  }
  return orig_fread(ptr, size, count, stream);
}

size_t (*orig_fwrite)(const void *ptr, size_t size, size_t count, FILE *stream);
size_t fake_fwrite(void *ptr, size_t size, size_t count, FILE *stream) {
  const char *file_name = GetFileDescriptorTraced(stream);
  if (file_name) {
    printf("[-] fwrite %s\n    from %p\n", file_name, ptr);
  }
  return orig_fwrite(ptr, size, count, stream);
}

__attribute__((constructor)) void __main() {

  TracedFileList = new std::unordered_map<FILE *, const char *>();

#if defined(__APPLE__)
#include <TargetConditionals.h>
#if (TARGET_OS_IPHONE || TARGET_OS_MAC)
  std::ifstream file;
  file.open("/System/Library/CoreServices/SystemVersion.plist");
  std::cout << file.rdbuf();
#endif
#endif

  DobbyHook((void *)fopen, (void *)fake_fopen, (void **)&orig_fopen);
  DobbyHook((void *)fwrite, (void *)fake_fwrite, (void **)&orig_fwrite);
  DobbyHook((void *)fread, (void *)fake_fread, (void **)&orig_fread);

  char *home   = getenv("HOME");
  char *subdir = (char *)"/Library/Caches/";

  std::string filePath = std::string(home) + std::string(subdir) + "temp.log";

  char buffer[64];
  memset(buffer, 'B', 64);

  FILE *fd = fopen(filePath.c_str(), "w+");
  if (!fd)
    std::cout << "[!] open " << filePath << "failed!\n";

  fwrite(buffer, 64, 1, fd);
  fflush(fd);
  fseek(fd, 0, SEEK_SET);
  memset(buffer, 0, 64);

  fread(buffer, 64, 1, fd);

  std::cout << "[*] HookExample End!\n";

  return;
}

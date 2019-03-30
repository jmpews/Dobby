//
//  YourHackL1b.cpp
//  HookExample
//
//  Created by jmpews on 2019/3/25.
//  Copyright © 2019 jmpews. All rights reserved.
//

#include "YourHackL1b.hpp"

#include <stdlib.h>     /* getenv */

#include <stdio.h>

#include <string.h>

#include <iostream>

#include <filesystem>
namespace fs = std::filesystem;


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

size_t (*orig_fwrite)(const void * ptr, size_t size, size_t count, FILE * stream);
size_t fake_fwrite(void *ptr, size_t size, size_t count, FILE *stream) {
  printf("fwrite: %p\n", ptr);
  memset(ptr, 'A', size * count);
  return orig_fwrite(ptr, size, count, stream);
}


__attribute__((constructor)) void _main() {
  
  ZzReplace((void *)fopen, (void *)fake_fopen, (void **)&orig_fopen);
  ZzReplace((void *)fwrite, (void *)fake_fwrite, (void **)&orig_fwrite);
  ZzReplace((void *)fread, (void *)fake_fread, (void **)&orig_fread);
  
  char *home = getenv("HOME");
  char *subdir = "/Library/Caches/";

  std::cout << "Current path is " << fs::current_path() << '\n';

  std::string filePath = std::string(home) + std::string(subdir) + "temp.log";
  
  char buffer[64];
  memset(buffer, 'B', 64);
  
  FILE *fd = fopen(filePath.c_str(), "w+");
  if(!fd)
    std::cout << "[!] open " << filePath << "failed!\n";

  fwrite(buffer, 64, 1, fd);
  fflush(fd);
  fseek(fd, 0, SEEK_SET);
  
  memset(buffer, 0, 64);
  
  fread(buffer, 64, 1, fd);
  
  std::cout << "[*] HookExample End!\n";
  
  return;
}

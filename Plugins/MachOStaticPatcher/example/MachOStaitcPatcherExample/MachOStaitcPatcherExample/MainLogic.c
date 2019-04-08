//
//  MainLogic.c
//  MachOStaitcPatcherExample
//
//  Created by jmpews on 2019/4/7.
//  Copyright © 2019 jmpews. All rights reserved.
//

#include "MainLogic.h"

#include <string.h>

void runMainFunction(char *name) {
  int x, y, z;
  x = 1;
  y = 2;
  z = x + y;
  
  int len = strlen(name);
  
  z += len;
  printf("MainFunctionLog %s, len %d.\n", name, z);
  return;
}

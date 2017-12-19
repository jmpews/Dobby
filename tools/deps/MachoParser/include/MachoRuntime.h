//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef MachoRuntime_h
#define MachoRuntime_h

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "objc/oobjc.h"
#include "Macho.h"

class MachoRuntime : public Macho
{
public:
  MachoRuntime();
  MachoRuntime(input_t input);

  bool parse_macho();
  void print_macho();

  virtual bool macho_read(zaddr addr, zpointer data, zsize len) = 0;
  virtual char *macho_read_string(zaddr addr) = 0;

  objc_class_info_t *parse_OBJECT(zaddr addr);
  bool oobject_isClass(zaddr object_addr);
  zaddr oobject_getClass(zaddr object_addr);

private:
};

#endif
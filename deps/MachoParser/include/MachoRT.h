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

#ifndef machort_h
#define machort_h

#include "macho.h"

#define MACHO_LOAD_ADDRESS 0x100000000

class MachoRT : public Macho {
public:
    MachoRT();

    MachoRT(input_t input);

    zaddr m_dyld_load_addr; //where is dyld load

    bool setPid(pid_t pid);

    bool searchBinLoadAddress();

    bool search_dyld_load_address(zaddr dyld_vm_addr);

    bool check_dyld_arch(zaddr addr);

    bool parse_dyld();
};

static MachoRT *mrt;

#endif //MACHOPARSER_MACHORT_H

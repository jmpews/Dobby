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

#ifndef MachoFD_h
#define MachoFD_h

#include "MachoFD.h"
#include "zz.h"

// common
#include <fcntl.h> //open
#include <stdio.h>
#include <sys/mman.h> //mmap
#include <sys/stat.h> //stat
#include <unistd.h> //read

#ifdef __cplusplus
extern "C" {
#endif
#include "zzdeps/common/LEB128.h"
#include "zzdeps/common/debugbreak.h"
#include "zzdeps/darwin/memory-utils-darwin.h"
#ifdef __cplusplus
}
#endif

MachoFD::MachoFD() : Macho()
{
    this->isRuntime = FALSE;
}

MachoFD::MachoFD(input_t input) : Macho(input)
{
    this->isRuntime = FALSE;
}

MachoFD::MachoFD(const char *path) : Macho()
{
    this->isRuntime = FALSE;
    this->setPath(path);
}

bool MachoFD::setPath(const char *path)
{
    int fd;
    zpointer data;

    /*
        ATTENTION:
        even not Jailbroken, still can read `/usr/lib/`, why?

        ref to : `the process of macho run`

        the kernel will load binary to memory at first, and then will load
       `/usr/lib/dyld` to load others dylib, so `/usr/lib/` must can be read.
     */

    fd = open(path, O_RDONLY);
    if (fd <= 0)
    {
        Xdebug("%s open failed", path);
        return FALSE;
    }

    struct stat st_buf;
    if (fstat(fd, &st_buf) != 0)
    {
        Xdebug("%s stat failed", path);
        return FALSE;
    }

    /* mmap */
    data = mmap(NULL, st_buf.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED)
    {
        Xerror("%s mmap failed", path);
        return FALSE;
    }
    this->load_addr = (zaddr)data;
    this->aslr_slide = 0;
    this->input.fd.fd = fd;
    this->input.fd.data = data;
    this->input.fd.baseAddr = (zaddr)data;
    this->input.fd.length = st_buf.st_size;
    this->input.type = FD_INPUT;
    return TRUE;
}

bool MachoFD::macho_read(zaddr address, zpointer data, zsize len)
{
    if (address - (zaddr)this->input.fd.data > this->input.fd.length)
    {
        return FALSE;
    }
    memcpy(data, (zpointer)address, len);
    return TRUE;
}
char *MachoFD::macho_read_string(zaddr address)
{
    return zz_vm_read_string((zpointer)address);
}
bool MachoFD::check_initialization()
{
    if (this->input.fd.fd <= 0)
    {
        Serror("MachoParser must be init.");
        return FALSE;
    }
    return TRUE;
}
void MachoFD::print_macho()
{
    Sinfo("print runtime macho:");

    Xinfo("image base: %p", (zpointer)this->load_addr);
    Xinfo("string table address: %p", (zpointer)this->linkinfo.strtab_offset);
    if (!this->isDyldLinker)
        Xinfo("dyld path: %s", this->dyld_path);
}

bool MachoFD::parse_macho()
{
    Sdebug("start dump macho...");
    do
    {
        if (!check_initialization())
        {
            break;
        }
        if (!parse_header())
            break;

        if (this->isFat)
        {
            parse_universal();
        }
        else
        {
            parse_load_command_headers();
            parse_load_command_details();
            parse_SECT();
        }

        return TRUE;
    } while (0);
    return FALSE;
}

#endif
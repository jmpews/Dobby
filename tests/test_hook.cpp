/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

extern "C" {
#include "../include/hookzz.h"
}

#include "MachoMem.h"

void patch_svc_pre_call(struct RegState_ *rs) {
    int request = (int) (uint64_t) (rs->general.regs.x0);
    if (request == 31) {
    }
    *(unsigned long *) (&rs->general.regs.x0) = 10;
}

__attribute__((constructor)) void parse_self() {
    const section_64_info_t *sect64;
    zaddr svc_x80_addr;
    zaddr curr_addr, end_addr;
    uint32_t svc_x80_byte = 0xd4001001;
    MachoMem *mem = new MachoMem();
    mem->parse_macho();
    mem->parse_dyld();
    sect64 = mem->get_sect_by_name("__text");
    curr_addr = sect64->sect_addr;
    end_addr = curr_addr + sect64->sect_64->size;

    ZZInitialize();
    while (curr_addr < end_addr) {
        svc_x80_addr = mem->macho_search_data(
                sect64->sect_addr, sect64->sect_addr + sect64->sect_64->size,
                (const zbyte *) &svc_x80_byte, 4);
        if (svc_x80_addr) {
            ZZBuildHook((void *) svc_x80_addr, NULL, NULL,
                        (zpointer) patch_svc_pre_call, NULL);
            ZZEnableHook((void *) svc_x80_addr);
            curr_addr = svc_x80_addr + 4;
        } else {
            break;
        }
    }
}

int (*oldfunc)(int, int, int, int);

extern int func(int x1, int x2, int x3, int x4);

int newfunc(int x1, int x2, int x3, int x4) {
    int t = 0;
    printf("[*] hook success\n");
    t = oldfunc(1, 2, 3, 4);
    printf("[+] result from oldfunc: %d\n", t);
    return 0;
}

int *orig_open;

void open_pre_call(struct RegState_ *rs) {
    zpointer openPath = (zpointer) (rs->general.regs.x0);
    int flag = (int) (rs->general.regs.x1);
    switch (flag & O_ACCMODE) {
        case O_RDONLY:
            printf("open:R:%s\n", openPath);
            break;
        case O_WRONLY:
            printf("open:W:%s\n", openPath);
            break;
        case O_RDWR:
            printf("open:RW:%s\n", openPath);
            break;
        default:
            break;
    }
}

__attribute__((constructor)) void test_hook_open() {
    ZZInitialize();
    ZZBuildHook((void *) open, NULL, (void **) (&orig_open),
                (zpointer) open_pre_call, NULL);
    ZZEnableHook((void *) open);
}

// TODO: bad code!!!
// move `recvmsg_data` to `hookentry`

#include <sys/socket.h>

int *orig_recvmsg;
zpointer recvmsg_data;

void recvmsg_pre_call(struct RegState_ *rs) {
    zpointer t = *((zpointer *) (rs->general.regs.x1) + 2);
    recvmsg_data = *(zpointer *) t;
}

void recvmsg_post_call(struct RegState_ *rs) {
    printf("@recvmsg@: %s\n", recvmsg_data);
}

__attribute__((constructor)) void test_hook_recvmsg() {
    ZZInitialize();
    ZZBuildHook((void *) recvmsg, NULL, (void **) (&orig_recvmsg),
                (zpointer) recvmsg_pre_call, (zpointer) recvmsg_post_call);
    // ZZEnableHook((void *) recvmsg);
}

int *orig_socket;
int socket_data = 0;

void socket_post_call(struct RegState_ *rs) {
    int socket_fd = (uint64_t) (rs->general.regs.x0);
    socket_data = socket_fd;
    printf("@socket@: fd:%d\n", socket_data);
}

__attribute__((constructor)) void test_hook_socket() {
    ZZInitialize();
    void *socket_ptr = (void *) socket;
    ZZBuildHook(socket_ptr, NULL, (void **) (&orig_socket), NULL,
                (zpointer) socket_post_call);
    // ZZEnableHook((void *) socket_ptr);
}

int *orig_read;
zpointer read_data = 0;

void read_pre_call(struct RegState_ *rs) {
    int fd = (uint64_t) (rs->general.regs.x0);
    if (4 == fd)
        read_data = (zpointer) (rs->general.regs.x1);
}

void read_post_call(struct RegState_ *rs) {
    int fd = (uint64_t) (rs->general.regs.x0);
    // if(4 == fd)
    printf("@read@: %s\n", read_data);
}

__attribute__((constructor)) void test_hook_read() {
    ZZInitialize();
    void *read_ptr = (void *) read;
    ZZBuildHook(read_ptr, NULL, (void **) (&orig_read), (zpointer) read_pre_call,
                (zpointer) read_post_call);
    // ZZEnableHook((void *) read_ptr);
}

// #include <objc/message.h>

// void test_msgSend_post_call(struct RegState_ *rs) {
//   printf("hook objc-method success.");
// }
// __attribute__((constructor)) void test_hook_TestClass() {
//   ZZInitialize();
//   ZZBuildHook(socket_ptr, NULL, (void **)(&orig_socket),
//               NULL, (zpointer)socket_post_call);
//   ZZEnableHook((void *)socket_ptr);
// }

// int main( int argc, const char* argv[]){
//     int t = 0;
//     ZZInitialize();
//     ZZBuildHook((void *)func, (void *)newfunc, (void **)(&oldfunc));
//     ZZEnableHook((void *)func);
//     t = func(1, 2, 3, 4);
//     printf("[+] result from newfunc: %d\n", t);

//     while (1)
//     {
//         sleep(1);
//         printf(".");
//         fflush(stdout);
//     }
// }

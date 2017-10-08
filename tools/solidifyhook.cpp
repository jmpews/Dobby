// `clang++ -L/Users/jmpews/Desktop/SpiderZz/project/HookZz/tools/deps/MachoParser/build -lmachoparser -o solidifyhook solidifyhook.cpp`
#include <iostream>
#include <stdio.h>
#include <mach-o/loader.h>

#include "deps/MachoParser/include/MachoFD.h"

using namespace std;

void zz_append_file_to_file(char *src_path, char *dst_path, unsigned long offset, unsigned long size)
{
    FILE *src_fd = fopen(src_path, "rb");
    FILE *dst_fd = fopen(dst_path, "ab");

    fseek(src_fd, offset, SEEK_SET);

    unsigned int WRITE_BLOCK_SIZE = 1024;
    unsigned char tmp_block[1024];

    for (int i = 0; i < size / WRITE_BLOCK_SIZE; i++)
    {
        fread(tmp_block, WRITE_BLOCK_SIZE, 1, src_fd);
        fwrite(tmp_block, WRITE_BLOCK_SIZE, 1, dst_fd);
    }

    if (size % WRITE_BLOCK_SIZE)
    {
        fread(tmp_block, size % WRITE_BLOCK_SIZE, 1, src_fd);
        fwrite(tmp_block, size % WRITE_BLOCK_SIZE, 1, dst_fd);
    }

    fclose(src_fd);
    fclose(dst_fd);
}

void zz_append_to_file(char *dst_path, void *content, unsigned long size)
{
    FILE *dst_fd = fopen(dst_path, "ab");
    fwrite(content, size, 1, dst_fd);
    fclose(dst_fd);
}

void macho_insert_segment(string target_path, string new_target_path)
{

    char *rx_segment_name = "HookZzCode";
    char *rw_segment_name = "HookZzData";

    MachoFD *machofd = new MachoFD(target_path.c_str());
    if (machofd->isFat)
    {
        printf("use lipo to thin it.");
    }
    const segment_command_64_info_t *seg_linkedit = machofd->get_seg_by_name("__LINKEDIT");

    struct mach_header_64 new_target_header;
    struct segment_command_64 new_target_rx_segment;
    struct segment_command_64 new_target_rw_segment;

    memcpy(machofd->header.header64, &new_target_header, sizeof(struct mach_header_64));
    memcpy(seg_linkedit->seg_cmd_64, &new_target_rx_segment, sizeof(struct segment_command_64));
    memcpy(seg_linkedit->seg_cmd_64, &new_target_rw_segment, sizeof(struct segment_command_64));

    memcpy(rx_segment_name, new_target_rx_segment.segname, strlen(rx_segment_name));

    memcpy(rw_segment_name, new_target_rw_segment.segname, strlen(rw_segment_name));

    new_target_header.ncmds += new_target_header.ncmds;

    zz_append_file_to_file(target_path.c_str(), new_target_path.c_str(), 0, (unsigned long)seg_linkedit->fileoff);
}

int main(int args, const char **argv)
{
    string target_file_path = "/Users/jmpews/Desktop/test/test.dylib";
    string new_target_file = "/Users/jmpews/Deskto/test/test.hook.dylib";
    MachoFD *machofd = new MachoFD(target_file_path.c_str());
}
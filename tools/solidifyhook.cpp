// `clang++ -L/Users/jmpews/Desktop/SpiderZz/project/HookZz/tools/deps/MachoParser/build
// -lmachoparser -o solidifyhook solidifyhook.cpp`

#include <iostream>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mach-o/loader.h>

#include "MachoFD.h"

void zz_debug() {
#ifdef DEBUGMODE
#ifdef ZZDEPS
    debug_break();
#else
    perror(NULL);
#endif
#endif
}

using namespace std;

unsigned long zz_file_get_size(const char *target_path) {
    unsigned long filesize = -1;
    struct stat statbuff;
    if (stat(target_path, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }
    return filesize;
}

bool zz_file_is_exist(const char *target_path) {
    if ((access(target_path, F_OK)) != -1) {
        return true;
    }
    return FALSE;
}

bool zz_file_remove(const char *target_path) {
    if (zz_file_is_exist(target_path)) {
        if (!remove(target_path)) {
            return TRUE;
        }
    }
    zz_debug();
    return FALSE;
}

void zz_write_file_to_file(const char *src_path, const char *dst_path, unsigned long src_offset,
                           unsigned long dst_offset, unsigned long size) {
    FILE *src_fd;
    FILE *dst_fd;
    src_fd = fopen(src_path, "rb");
    fseek(src_fd, src_offset, SEEK_SET);

    if (!zz_file_is_exist(dst_path))
        dst_fd = fopen(dst_path, "wb");
    else
        dst_fd = fopen(dst_path, "rb+");

    fseek(dst_fd, dst_offset, SEEK_SET);

    unsigned int WRITE_BLOCK_SIZE = 1024;
    unsigned char tmp_block[1024];

    for (int i = 0; i < size / WRITE_BLOCK_SIZE; i++) {
        fread(tmp_block, WRITE_BLOCK_SIZE, 1, src_fd);
        fwrite(tmp_block, WRITE_BLOCK_SIZE, 1, dst_fd);
    }

    if (size % WRITE_BLOCK_SIZE) {
        fread(tmp_block, size % WRITE_BLOCK_SIZE, 1, src_fd);
        fwrite(tmp_block, size % WRITE_BLOCK_SIZE, 1, dst_fd);
    }

    fclose(src_fd);
    fclose(dst_fd);
}

void zz_copy_file_to_file(const char *src_path, const char *dst_path) {
    unsigned long file_size;
    file_size = zz_file_get_size(src_path);
    zz_write_file_to_file(src_path, dst_path, 0, 0, file_size);
}

void zz_write_to_file(const char *dst_path, unsigned long offset, void *content,
                      unsigned long size) {
    FILE *dst_fd = fopen(dst_path, "rb+");
    fseek(dst_fd, offset, SEEK_SET);
    fwrite(content, size, 1, dst_fd);
    fclose(dst_fd);
}

void zz_write_append_to_file(const char *dst_path, void *content, unsigned long size) {
    FILE *dst_fd = fopen(dst_path, "ab+");
    fwrite(content, size, 1, dst_fd);
    fclose(dst_fd);
}
unsigned long zz_get_linkedit_offset(MachoFD *machofd) {
    for (const auto &loadcmd : machofd->loadcommands.load_command_infos) {
        /* iterate dump section */
        if (loadcmd.load_cmd->cmd == LC_SEGMENT_64) {
            if (!strcmp(((struct segment_command_64 *)loadcmd.cmd_info)->segname, "__LINKEDIT"))
                return loadcmd.fileoff;
        }
    }
    return NULL;
}

void zz_fix_load_command(const char *target_path) {
    MachoFD *machofd = new MachoFD(target_path);
    if (machofd->isFat) {
        printf("use lipo to thin it.");
    }
    machofd->parse_macho();

    for (const auto &loadcmd : machofd->loadcommands.load_command_infos) {
        if (loadcmd.load_cmd->cmd == LC_DYLD_INFO_ONLY) {
            struct dyld_info_command *tmp = (struct dyld_info_command *)loadcmd.cmd_info;
            struct dyld_info_command new_tmp = *tmp;
            new_tmp.rebase_off += 0x8000;
            new_tmp.bind_off += 0x8000;
            if (new_tmp.weak_bind_off)
                new_tmp.weak_bind_off += 0x8000;
            if (new_tmp.lazy_bind_off)
                new_tmp.lazy_bind_off += 0x8000;
            if (new_tmp.export_off)
                new_tmp.export_off += 0x8000;
            zz_write_to_file(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));
        }
        if (loadcmd.load_cmd->cmd == LC_SYMTAB) {
            struct symtab_command *tmp = (struct symtab_command *)loadcmd.cmd_info;
            struct symtab_command new_tmp = *tmp;
            if (new_tmp.symoff)
                new_tmp.symoff += 0x8000;
            if (new_tmp.stroff)
                new_tmp.stroff += 0x8000;
            zz_write_to_file(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));
        }
        if (loadcmd.load_cmd->cmd == LC_DYSYMTAB) {
            struct dysymtab_command *tmp = (struct dysymtab_command *)loadcmd.cmd_info;
            struct dysymtab_command new_tmp = *tmp;
            if (new_tmp.tocoff)
                new_tmp.tocoff += 0x8000;
            if (new_tmp.modtaboff)
                new_tmp.modtaboff += 0x8000;
            if (new_tmp.extrefsymoff)
                new_tmp.extrefsymoff += 0x8000;
            if (new_tmp.indirectsymoff)
                new_tmp.indirectsymoff += 0x8000;
            if (new_tmp.extreloff)
                new_tmp.extreloff += 0x8000;
            if (new_tmp.locreloff)
                new_tmp.locreloff += 0x8000;
            zz_write_to_file(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));
        }
        if (loadcmd.load_cmd->cmd == LC_FUNCTION_STARTS ||
            loadcmd.load_cmd->cmd == LC_DATA_IN_CODE) {
            struct linkedit_data_command *tmp = (struct linkedit_data_command *)loadcmd.cmd_info;
            struct linkedit_data_command new_tmp = *tmp;
            if (new_tmp.dataoff)
                new_tmp.dataoff += 0x8000;
            zz_write_to_file(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));
        }
    }
}

void zz_file_move_offset_to_offset(const char *target_path, unsigned long src_offset,
                                   unsigned long dst_offset, unsigned long size) {
    FILE *target_fd;
    target_fd = fopen(target_path, "rb+");
    unsigned char *data = (unsigned char *)malloc(size);
    fseek(target_fd, src_offset, SEEK_SET);
    fread(data, size, 1, target_fd);
    fseek(target_fd, dst_offset, SEEK_SET);
    fwrite(data, size, 1, target_fd);
    free(data);
    fclose(target_fd);
}

void macho_insert_segment(string target_path, string new_target_path) {

    char *rx_segment_name = "HookZzCode";
    char *rw_segment_name = "HookZzData";

    MachoFD *machofd = new MachoFD(target_path.c_str());
    if (machofd->isFat) {
        printf("use lipo to thin it.");
    }
    machofd->parse_macho();
    const segment_command_64_info_t *seg_linkedit = machofd->get_seg_by_name("__LINKEDIT");

    struct mach_header_64 new_target_header;
    struct segment_command_64 new_target_rx_segment;
    struct segment_command_64 new_target_rw_segment;
    struct segment_command_64 new_target_linkedit_segment;

    memcpy(&new_target_header, machofd->header.header64, sizeof(struct mach_header_64));
    memcpy(&new_target_rx_segment, seg_linkedit->seg_cmd_64, sizeof(struct segment_command_64));
    memcpy(&new_target_rw_segment, seg_linkedit->seg_cmd_64, sizeof(struct segment_command_64));
    memcpy(&new_target_linkedit_segment, seg_linkedit->seg_cmd_64,
           sizeof(struct segment_command_64));

    // add new rx segment
    memcpy(new_target_rx_segment.segname, rx_segment_name, strlen(rx_segment_name));
    new_target_rx_segment.vmsize = 0x4000;
    new_target_rx_segment.filesize = 0x4000;
    new_target_rx_segment.vmaddr = new_target_rx_segment.vmaddr;
    new_target_rx_segment.fileoff = new_target_rx_segment.fileoff;
    new_target_rx_segment.maxprot = 5;
    new_target_rx_segment.initprot = 5;

    // add new rw segment
    memcpy(new_target_rw_segment.segname, rw_segment_name, strlen(rw_segment_name));
    new_target_rw_segment.vmsize = 0x4000;
    new_target_rw_segment.filesize = 0x4000;
    new_target_rw_segment.vmaddr = new_target_rw_segment.vmaddr + 0x4000;
    new_target_rw_segment.fileoff = new_target_rw_segment.fileoff + 0x4000;
    new_target_rw_segment.maxprot = 5;
    new_target_rw_segment.initprot = 5;

    // fix linkedit segment
    new_target_linkedit_segment.vmaddr = new_target_linkedit_segment.vmaddr + 0x4000 + 0x4000;
    new_target_linkedit_segment.fileoff = new_target_linkedit_segment.fileoff + 0x4000 + 0x4000;

    // fix header
    new_target_header.ncmds += 2;
    new_target_header.sizeofcmds += (new_target_rx_segment.cmdsize + new_target_rw_segment.cmdsize);

    //    zz_copy_file_to_file(target_path.c_str(), new_target_path.c_str());
    zz_write_file_to_file(target_path.c_str(), new_target_path.c_str(), 0, 0,
                          seg_linkedit->seg_cmd_64->fileoff);

    unsigned long orig_linkedit_offset = zz_get_linkedit_offset(machofd);
    unsigned long move_size =
        machofd->header.header64->sizeofcmds + sizeof(struct mach_header_64) - orig_linkedit_offset;
    unsigned long new_linkedit_offset =
        orig_linkedit_offset + (new_target_rx_segment.cmdsize + new_target_rw_segment.cmdsize);
    zz_file_move_offset_to_offset(new_target_path.c_str(), orig_linkedit_offset,
                                  new_linkedit_offset, move_size);

    zz_write_to_file(new_target_path.c_str(), 0, &new_target_header, sizeof(new_target_header));
    zz_write_to_file(new_target_path.c_str(), orig_linkedit_offset, &new_target_rx_segment,
                     sizeof(struct segment_command_64));
    zz_write_to_file(new_target_path.c_str(), orig_linkedit_offset + new_target_rx_segment.cmdsize,
                     &new_target_rw_segment, sizeof(struct segment_command_64));
    zz_write_to_file(new_target_path.c_str(),
                     orig_linkedit_offset + new_target_rx_segment.cmdsize +
                         new_target_rw_segment.cmdsize,
                     &new_target_linkedit_segment, sizeof(struct segment_command_64));

    char segment_blank[0x4000] = {0};
    zz_write_append_to_file(new_target_path.c_str(), &segment_blank, 0x4000);
    zz_write_append_to_file(new_target_path.c_str(), &segment_blank, 0x4000);
    zz_write_file_to_file(target_path.c_str(), new_target_path.c_str(),
                          seg_linkedit->seg_cmd_64->fileoff, new_target_linkedit_segment.fileoff,
                          zz_file_get_size(target_path.c_str()) -
                              seg_linkedit->seg_cmd_64->fileoff);
}

int main(int args, const char **argv) {
    string target_file_path = "/Users/jmpews/Desktop/test/test.dylib";
    string new_target_file_path = "/Users/jmpews/Desktop/test/test.hook.dylib";

    zz_file_remove(new_target_file_path.c_str());
    macho_insert_segment(target_file_path, new_target_file_path);
    zz_fix_load_command(new_target_file_path.c_str());
}
#include <iostream>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/loader.h>

using namespace std;

typedef unsigned long zz_size_t;

zz_size_t zz_file_get_size(const char *target_path) {
    zz_size_t filesize = -1;
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
        return TRUE;
    }
    return FALSE;
}

bool zz_file_remove(const char *target_path) {
    if (zz_file_is_exist(target_path)) {
        if (!remove(target_path)) {
            return TRUE;
        }
    }
    return FALSE;
}

bool zz_file_copy_offset(const char *src_path, const char *dst_path, zz_size_t src_offset, zz_size_t dst_offset, zz_size_t length) {
    FILE *src_fd;
    FILE *dst_fd;

    if (!zz_file_is_exist(src_path) || !zz_file_is_exist(dst_path)) {
        return FALSE;
    }

    src_fd = fopen(src_path, "rb");
    dst_fd = fopen(dst_path, "rb+");

    fseek(src_fd, src_offset, SEEK_SET);
    fseek(dst_fd, dst_offset, SEEK_SET);

    zz_size_t WRITE_BLOCK_SIZE = 1024;
    unsigned char tmp_block[1024];

    for (int i = 0; i < length / WRITE_BLOCK_SIZE; i++) {
        fread(tmp_block, WRITE_BLOCK_SIZE, 1, src_fd);
        fwrite(tmp_block, WRITE_BLOCK_SIZE, 1, dst_fd);
    }

    if (length % WRITE_BLOCK_SIZE) {
        fread(tmp_block, length % WRITE_BLOCK_SIZE, 1, src_fd);
        fwrite(tmp_block, length % WRITE_BLOCK_SIZE, 1, dst_fd);
    }

    fclose(src_fd);
    fclose(dst_fd);
    return TRUE;
}

void zz_copy_file_to_file(const char *src_path, const char *dst_path) {
    zz_size_t file_size;
    file_size = zz_file_get_size(src_path);
    zz_file_copy_offset(src_path, dst_path, 0, 0, file_size);
}

void zz_file_write(const char *dst_path, zz_size_t offset, void *content, zz_size_t length) {
    FILE *dst_fd = fopen(dst_path, "rb+");
    fseek(dst_fd, offset, SEEK_SET);
    fwrite(content, length, 1, dst_fd);
    fclose(dst_fd);
}

void zz_file_read(const char *dst_path, zz_size_t offset, void *content, zz_size_t length) {
    FILE *dst_fd = fopen(dst_path, "rb");
    fseek(dst_fd, offset, SEEK_SET);
    fread(content, length, 1, dst_fd);
    fclose(dst_fd);
}

void zz_file_append_write(const char *dst_path, void *content, zz_size_t length) {
    FILE *dst_fd = fopen(dst_path, "ab+");
    fwrite(content, length, 1, dst_fd);
    fclose(dst_fd);
}

void zz_file_move_offset_to_offset(const char *target_path, zz_size_t src_offset, zz_size_t dst_offset,
                                   zz_size_t length) {
    FILE *target_fd;
    target_fd = fopen(target_path, "rb+");
    unsigned char *data = (unsigned char *)malloc(length);
    fseek(target_fd, src_offset, SEEK_SET);
    fread(data, length, 1, target_fd);
    fseek(target_fd, dst_offset, SEEK_SET);
    fwrite(data, length, 1, target_fd);
    free(data);
    fclose(target_fd);
}

zz_size_t macho_get_linkedit_loadcmd_fileoff(macho_header) {
    for (const auto &loadcmd : machofd->loadcommands.load_command_infos) {
        /* iterate dump section */
        if (loadcmd.load_cmd->cmd == LC_SEGMENT_64) {
            if (!strcmp(((struct segment_command_64 *)loadcmd.cmd_info)->segname, "__LINKEDIT"))
                return loadcmd.fileoff;
        }
    }
    return 0;
}

void fix_macho_load_command(const char *target_path) {
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
            zz_file_write(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));
            Sinfo("[*] fix LC_DYLD_INFO_ONLY done");
        }
        if (loadcmd.load_cmd->cmd == LC_SYMTAB) {
            struct symtab_command *tmp = (struct symtab_command *)loadcmd.cmd_info;
            struct symtab_command new_tmp = *tmp;
            if (new_tmp.symoff)
                new_tmp.symoff += 0x8000;
            if (new_tmp.stroff)
                new_tmp.stroff += 0x8000;
            zz_file_write(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));
            Sinfo("[*] fix LC_SYMTAB done");
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
            zz_file_write(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));
            Sinfo("[*] fix LC_DYSYMTAB done");
        }
        if (loadcmd.load_cmd->cmd == LC_FUNCTION_STARTS || loadcmd.load_cmd->cmd == LC_DATA_IN_CODE) {
            struct linkedit_data_command *tmp = (struct linkedit_data_command *)loadcmd.cmd_info;
            struct linkedit_data_command new_tmp = *tmp;
            if (new_tmp.dataoff)
                new_tmp.dataoff += 0x8000;
            zz_file_write(target_path, loadcmd.fileoff, &new_tmp, sizeof(new_tmp));

            Sinfo("[*] fix LC_FUNCTION_STARTS/LC_DATA_IN_CODE done");
        }
    }
}

void macho_insert_segment(string target_path, string new_target_path) {

    char *rx_segment_name = (char *)"HookZzCode";
    char *rw_segment_name = (char *)"HookZzData";
    MachoFD *machofd = new MachoFD(target_path.c_str());

    Sinfo("[*] start insert rw- and r-x segments");

    if (machofd->isFat) {
        printf("use lipo to thin it.");
    }
    machofd->parse_macho();
    Xinfo("[*] parse origin file %s", target_path.c_str());

    const segment_command_64_info_t *seg_linkedit = machofd->get_seg_by_name("__LINKEDIT");

    struct mach_header_64 new_target_header;
    struct segment_command_64 new_target_rx_segment;
    struct segment_command_64 new_target_rw_segment;
    struct segment_command_64 new_target_linkedit_segment;

    memcpy(&new_target_header, machofd->header.header64, sizeof(struct mach_header_64));
    memcpy(&new_target_rx_segment, seg_linkedit->seg_cmd_64, sizeof(struct segment_command_64));
    memcpy(&new_target_rw_segment, seg_linkedit->seg_cmd_64, sizeof(struct segment_command_64));
    memcpy(&new_target_linkedit_segment, seg_linkedit->seg_cmd_64, sizeof(struct segment_command_64));

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
    new_target_rw_segment.maxprot = 3;
    new_target_rw_segment.initprot = 3;

    // fix linkedit segment
    new_target_linkedit_segment.vmaddr = new_target_linkedit_segment.vmaddr + 0x4000 + 0x4000;
    new_target_linkedit_segment.fileoff = new_target_linkedit_segment.fileoff + 0x4000 + 0x4000;

    zz_file_copy_offset(target_path.c_str(), new_target_path.c_str(), 0, 0, seg_linkedit->seg_cmd_64->fileoff);

    /* fix linkedit segment, move it */
    unsigned long orig_linkedit_offset = zz_macho_get_linkedit_loadcmd_fileoff(machofd);
    unsigned long move_size =
        machofd->header.header64->sizeofcmds + sizeof(struct mach_header_64) - orig_linkedit_offset;
    unsigned long new_linkedit_offset =
        orig_linkedit_offset + (new_target_rx_segment.cmdsize + new_target_rw_segment.cmdsize);
    unsigned char tmp_buffer = (unsigned char *)malloc(move_size);
    zz_file_read(new_target_path.c_str(), orig_linkedit_offset, tmp_buffer, move_size);
    zz_file_write(new_target_path.c_str(), new_linkedit_offset, move_size);

    // fix header
    new_target_header.ncmds += 2;
    new_target_header.sizeofcmds += (new_target_rx_segment.cmdsize + new_target_rw_segment.cmdsize);
    zz_file_write(new_target_path.c_str(), 0, &new_target_header, sizeof(new_target_header));
    Sinfo("[*] fix macho header");

    zz_file_write(new_target_path.c_str(), orig_linkedit_offset, &new_target_rx_segment,
                  sizeof(struct segment_command_64));
    Sinfo("[*] add \'HookZzCode(r-x)\' Segment");
    zz_file_write(new_target_path.c_str(), orig_linkedit_offset + new_target_rx_segment.cmdsize, &new_target_rw_segment,
                  sizeof(struct segment_command_64));
    Sinfo("[*] add \'HookZzData(rw-)\' Segment");
    zz_file_write(new_target_path.c_str(),
                  orig_linkedit_offset + new_target_rx_segment.cmdsize + new_target_rw_segment.cmdsize,
                  &new_target_linkedit_segment, sizeof(struct segment_command_64));
    Sinfo("[*] fix \'__LINKEDIT\' Segment");

    char segment_blank[0x4000] = {0};
    zz_file_append_write(new_target_path.c_str(), &segment_blank, 0x4000);
    Xinfo("[*] reserve %p length space to HookZzCode Segment", (zpointer)0x4000);
    zz_file_append_write(new_target_path.c_str(), &segment_blank, 0x4000);
    Xinfo("[*] reserve %p length space to HookZzData Segment", (zpointer)0x4000);
    zz_file_copy_offset(target_path.c_str(), new_target_path.c_str(), seg_linkedit->seg_cmd_64->fileoff,
                        new_target_linkedit_segment.fileoff,
                        zz_file_get_size(target_path.c_str()) - seg_linkedit->seg_cmd_64->fileoff);

    /* fix load command */
    fix_macho_load_command(new_target_path.c_str());
}

typedef struct _InterceptorBackendNoJB {
    void *enter_thunk; // hardcode
    void *leave_thunk; // hardcode
    void *function_context_begin_invocation;
    void *function_context_end_invocation;
    unsigned long num_of_entry;
    unsigned long code_seg_offset;
    unsigned long data_seg_offset;
} InterceptorBackendNoJB;

typedef struct _HookEntryNoJB {
    void *target_fileoff;
    unsigned long is_near_jump;
    void *entry_address;
    void *on_enter_trampoline;  // HookZzData, 99% hardcode
    void *on_invoke_trampoline; // HookZzData, fixed instructions
    void *on_leave_trampoline;  // HookZzData, 99% hardcode
} HookEntryNoJB;

//------------------------------------------------------------
//-----------       Created with 010 Editor        -----------
//------         www.sweetscape.com/010editor/          ------
//
// File    : /Users/jmpews/Desktop/SpiderZz/project/HookZz/tools/ZzSolidifyHook/solidifytrampoline.dylib
// Address : 32456 (0x7EC8)
// Size    : 84 (0x54)
//------------------------------------------------------------
unsigned char on_enter_trampoline_template[84] = {
    0xFF, 0x43, 0x00, 0xD1, 0xF0, 0x03, 0x1F, 0xF8, 0x10, 0x00, 0x00, 0x10, 0x51, 0x00, 0x00, 0x58, 0x03,
    0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x02, 0x10, 0x8B, 0xF0, 0x07,
    0x41, 0xF8, 0x31, 0x02, 0x40, 0xF9, 0xF1, 0x03, 0x00, 0xF9, 0xF0, 0x03, 0x1F, 0xF8, 0x10, 0x00, 0x00,
    0x10, 0x51, 0x00, 0x00, 0x58, 0x03, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0x02, 0x10, 0x8B, 0xF0, 0x07, 0x41, 0xF8, 0x31, 0x02, 0x40, 0xF9, 0x20, 0x02, 0x1F, 0xD6};
#define ON_ENTER_TRAMPOLINE_SIZE 84

//------------------------------------------------------------
//-----------       Created with 010 Editor        -----------
//------         www.sweetscape.com/010editor/          ------
//
// File    : /Users/jmpews/Desktop/SpiderZz/project/HookZz/tools/ZzSolidifyHook/solidifytrampoline.dylib
// Address : 32540 (0x7F1C)
// Size    : 72 (0x48)
//------------------------------------------------------------
unsigned char on_invoke_trampoline_template[72] = {
    0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20,
    0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0xF0, 0x03, 0x1F, 0xF8,
    0x10, 0x00, 0x00, 0x10, 0x51, 0x00, 0x00, 0x58, 0x03, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x31, 0x02, 0x10, 0x8B, 0xF0, 0x07, 0x41, 0xF8, 0x31, 0x02, 0x40, 0xF9, 0x20, 0x02, 0x1F, 0xD6};
#define ON_INVOKE_TRAMPOLINE_SIZE 72

//------------------------------------------------------------
//-----------       Created with 010 Editor        -----------
//------         www.sweetscape.com/010editor/          ------
//
// File    : /Users/jmpews/Desktop/SpiderZz/project/HookZz/tools/ZzSolidifyHook/solidifytrampoline.dylib
// Address : 32612 (0x7F64)
// Size    : 84 (0x54)
//------------------------------------------------------------

unsigned char on_leave_trampoline_template[84] = {
    0xFF, 0x43, 0x00, 0xD1, 0xF0, 0x03, 0x1F, 0xF8, 0x10, 0x00, 0x00, 0x10, 0x51, 0x00, 0x00, 0x58, 0x03,
    0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x02, 0x10, 0x8B, 0xF0, 0x07,
    0x41, 0xF8, 0x31, 0x02, 0x40, 0xF9, 0xF1, 0x03, 0x00, 0xF9, 0xF0, 0x03, 0x1F, 0xF8, 0x10, 0x00, 0x00,
    0x10, 0x51, 0x00, 0x00, 0x58, 0x03, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0x02, 0x10, 0x8B, 0xF0, 0x07, 0x41, 0xF8, 0x31, 0x02, 0x40, 0xF9, 0x20, 0x02, 0x1F, 0xD6};

#define ON_LEAVE_TRAMPOLINE_SIZE 84

void ZzSolidifyBuildEnterTrampoline(InterceptorBackendNoJB *nojb_backend, HookEntryNoJB *nojb_entry,
                                    MachoFD *machofd) {

    const char *target_path = machofd->getPath();
    const segment_command_64_info_t *code_seg_info = machofd->get_seg_by_name((char *)"HookZzCode");
    const segment_command_64_info_t *data_seg_info = machofd->get_seg_by_name((char *)"HookZzData");

    unsigned char on_enter_trampoline_tp[256] = {0};
    zsize ENTER_TRAMPOLINE_SIZE = 21 * 4;

    Sinfo("[*] solidify build on_enter_trampoline");
    memcpy(on_enter_trampoline_tp, (void *)on_enter_trampoline_template, ENTER_TRAMPOLINE_SIZE);

    zaddr data_vmaddr = (zaddr)data_seg_info->vmaddr + sizeof(InterceptorBackendNoJB) +
                        nojb_backend->num_of_entry * sizeof(HookEntryNoJB) + 2 * sizeof(void *);
    zaddr codepatch_vmaddr = code_seg_info->vmaddr + +2 * 4;
    zaddr offset = data_vmaddr - codepatch_vmaddr;
    *(unsigned long *)&on_enter_trampoline_tp[5 * 4] = (unsigned long)offset;

    data_vmaddr = data_seg_info->vmaddr + 0x8 * 0;
    codepatch_vmaddr = code_seg_info->vmaddr + (zaddr)nojb_backend->code_seg_offset + 15 * 4;
    offset = data_vmaddr - codepatch_vmaddr;
    *(unsigned long *)&on_enter_trampoline_tp[15 * 4] = (unsigned long)offset;

    zz_file_write(target_path, code_seg_info->fileoff + nojb_backend->code_seg_offset, on_enter_trampoline_tp,
                  ENTER_TRAMPOLINE_SIZE);
    nojb_entry->on_enter_trampoline = (zpointer)(code_seg_info->vmaddr + nojb_backend->code_seg_offset);
    nojb_backend->code_seg_offset += ENTER_TRAMPOLINE_SIZE;
}

void ZzSolidifyBuildInvokeTrampoline(InterceptorBackendNoJB *nojb_backend, HookEntryNoJB *nojb_entry,
                                     MachoFD *machofd) {
    const char *target_path = machofd->getPath();
    const segment_command_64_info_t *code_seg_info = machofd->get_seg_by_name((char *)"HookZzCode");
    const segment_command_64_info_t *data_seg_info = machofd->get_seg_by_name((char *)"HookZzData");
    zpointer target_fileoff = nojb_entry->target_fileoff;
    unsigned char on_invoke_trampoline_tp[256] = {0};
    zsize INVOKE_TRAMPOLINE_SIZE = 18 * 4;

    uint32_t insn;
    Sinfo("[*] solidify build on_invoke_trampoline");
    memcpy(on_invoke_trampoline_tp, (void *)on_invoke_trampoline_template, INVOKE_TRAMPOLINE_SIZE);

    zz_file_read(target_path, (zaddr)target_fileoff, &insn, 4);
    memcpy(on_invoke_trampoline_tp, &insn, 4);

    // from on_invoke_trampoline jump to origin rest code
    // TODO:
    zaddr offset = (zaddr)target_fileoff + 4 - (zaddr)nojb_entry->on_enter_trampoline - 4;
    insn = 0x14000000;
    insn = insn | ((offset / 4) & 0x03ffffff);
    *(uint32_t *)&on_invoke_trampoline_tp[4] = insn;

    nojb_entry->is_near_jump = TRUE;

    zz_file_write(target_path, code_seg_info->fileoff + nojb_backend->code_seg_offset, on_invoke_trampoline_tp,
                  INVOKE_TRAMPOLINE_SIZE);
    nojb_entry->on_invoke_trampoline = (zpointer)(code_seg_info->vmaddr + nojb_backend->code_seg_offset);
    nojb_backend->code_seg_offset += INVOKE_TRAMPOLINE_SIZE;
}

void ZzSolidifyBuildLeaveTrampoline(InterceptorBackendNoJB *nojb_backend, HookEntryNoJB *nojb_entry,
                                    MachoFD *machofd) {

    const char *target_path = machofd->getPath();
    const segment_command_64_info_t *code_seg_info = machofd->get_seg_by_name((char *)"HookZzCode");
    const segment_command_64_info_t *data_seg_info = machofd->get_seg_by_name((char *)"HookZzData");

    unsigned char on_leave_trampoline_tp[256] = {0};
    zsize LEAVE_TRAMPOLINE_SIZE = 21 * 4;

    Sinfo("[*] solidify build on_leave_trampoline");
    memcpy(on_leave_trampoline_tp, (void *)on_leave_trampoline_template, LEAVE_TRAMPOLINE_SIZE);

    zaddr data_vmaddr = (zaddr)data_seg_info->vmaddr + sizeof(InterceptorBackendNoJB) +
                        nojb_backend->num_of_entry * sizeof(HookEntryNoJB) + 2 * sizeof(void *);
    zaddr codepatch_vmaddr = code_seg_info->vmaddr + +2 * 4;
    zaddr offset = data_vmaddr - codepatch_vmaddr;
    *(unsigned long *)&on_leave_trampoline_tp[5 * 4] = (unsigned long)offset;

    data_vmaddr = data_seg_info->vmaddr + 0x8 * 1;
    codepatch_vmaddr = code_seg_info->vmaddr + (zaddr)nojb_backend->code_seg_offset + 12 * 4;
    offset = data_vmaddr - codepatch_vmaddr;
    *(unsigned long *)&on_leave_trampoline_tp[15 * 4] = (unsigned long)offset;

    zz_file_write(target_path, code_seg_info->fileoff + nojb_backend->code_seg_offset, on_leave_trampoline_tp,
                  LEAVE_TRAMPOLINE_SIZE);
    nojb_entry->on_leave_trampoline = (zpointer)(code_seg_info->vmaddr + nojb_backend->code_seg_offset);
    nojb_backend->code_seg_offset += LEAVE_TRAMPOLINE_SIZE;
}

void ZzSolidifyHookInitilize(InterceptorBackendNoJB *nojb_backend, MachoFD *machofd) {
    const char *target_path = machofd->getPath();
    const segment_command_64_info_t *code_seg_info = machofd->get_seg_by_name((char *)"HookZzCode");
    const segment_command_64_info_t *data_seg_info = machofd->get_seg_by_name((char *)"HookZzData");

    Sinfo("[*] solidify hook initilize");
    zz_file_read(target_path, data_seg_info->fileoff, nojb_backend, sizeof(InterceptorBackendNoJB));
    nojb_backend->code_seg_offset = 0;
}

void ZzSolidifyHookActivate(HookEntryNoJB *nojb_entry, MachoFD *machofd) {
    zpointer target_fileoff = nojb_entry->target_fileoff;
    const char *target_path = machofd->getPath();

    // try near jump
    if (nojb_entry->is_near_jump) {
        zaddr near_jump_offset = (zaddr)nojb_entry->on_enter_trampoline - (zaddr)target_fileoff;
        uint32_t insn = 0x14000000;
        insn = insn | ((near_jump_offset / 4) & 0x03ffffff);
        zz_file_write(target_path, (zaddr)target_fileoff, &insn, 4);
    }
}

void ZzSolidifyHook(zpointer target_fileoff, MachoFD *machofd) {
    const char *target_path = machofd->getPath();
    const segment_command_64_info_t *code_seg_info = machofd->get_seg_by_name((char *)"HookZzCode");
    const segment_command_64_info_t *data_seg_info = machofd->get_seg_by_name((char *)"HookZzData");

    InterceptorBackendNoJB nojb_backend;
    HookEntryNoJB nojb_entry;
    ZzSolidifyHookInitilize(&nojb_backend, machofd);

    Xinfo("[*] start solidify hook at %p", target_fileoff);

    nojb_entry.target_fileoff = target_fileoff;
    ZzSolidifyBuildEnterTrampoline(&nojb_backend, &nojb_entry, machofd);
    ZzSolidifyBuildInvokeTrampoline(&nojb_backend, &nojb_entry, machofd);
    ZzSolidifyBuildLeaveTrampoline(&nojb_backend, &nojb_entry, machofd);

    /* solidify new hook entry to file */
    zz_file_write(target_path, data_seg_info->fileoff + sizeof(HookEntryNoJB) * nojb_backend.num_of_entry,
                  &nojb_entry, sizeof(HookEntryNoJB));

    /* solidify update interceptor backend to file */
    nojb_backend.num_of_entry += 1;
    zz_file_write(target_path, data_seg_info->fileoff, &nojb_backend, sizeof(InterceptorBackendNoJB));

    ZzSolidifyHookActivate(&nojb_entry, machofd);
}

int main(int args, const char **argv) {
    string target_file_path = "/Users/jmpews/Desktop/test/test.dylib";
    string new_target_file_path = target_file_path;
    new_target_file_path.insert(new_target_file_path.rfind('.'), ".hook");

    zz_file_remove(new_target_file_path.c_str());

    macho_insert_segment(target_file_path, new_target_file_path);

    MachoFD *machofd = new MachoFD(new_target_file_path.c_str());
    if (machofd->isFat) {
        printf("use lipo to thin it.");
    }
    machofd->parse_macho();

    ZzSolidifyHook((zpointer)0x7f0c, machofd);
}

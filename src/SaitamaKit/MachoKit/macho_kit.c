#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <mach/task_info.h>

#include "MachoKit/macho_kit.h"

// get dyld load address by task_info, TASK_DYLD_INFO
zz_ptr_t zz_macho_get_dyld_load_address_via_task(task_t task) {
    // http://stackoverflow.com/questions/4309117/determining-programmatically-what-modules-are-loaded-in-another-process-os-x
    kern_return_t kr;
    task_flavor_t flavor = TASK_DYLD_INFO;
    task_dyld_info_data_t infoData;
    mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
    kr                                      = task_info(task, flavor, (task_info_t)&infoData, &task_info_outCnt);
    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return 0;
    }
    struct dyld_all_image_infos *allImageInfos = (struct dyld_all_image_infos *)infoData.all_image_info_addr;
    allImageInfos = (struct dyld_all_image_infos *)malloc(sizeof(struct dyld_all_image_infos));
    if (zz_darwin_vm_read_data_via_task(task, infoData.all_image_info_addr, allImageInfos,
                                        sizeof(struct dyld_all_image_infos))) {
        return (zz_ptr_t)(allImageInfos->dyldImageLoadAddress);
    } else {
        return NULL;
    }
}

task_t zz_darwin_get_task_via_pid(int pid) {
    task_t t;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
    if (kr != KERN_SUCCESS) {
        ZZ_KR_ERROR_LOG(kr);
        return 0;
    }
    return t;
}

sgmt_cmd *zz_macho_get_segment_via_name(mach_hdr *header, char *segment_name) {
    load_cmd *loadCmd;
    sgmt_cmd *sgmtCmd;
    sect_cmd *sectCmd;

    loadCmd = (zz_ptr_t)header + sizeof(mach_hdr);
    zz_size_t i;
    for (i = 0; i < header->ncmds; i++, loadCmd = (zz_ptr_t)loadCmd + loadCmd->cmdsize) {
        if (loadCmd->cmd == LC_SGMT) {
            sgmtCmd = (sgmt_cmd *)loadCmd;
            if (!strcmp(sgmtCmd->segname, segment_name)) {
                return sgmtCmd;
            }
        }
    }
    return NULL;
}

sect_cmd *zz_macho_get_section_via_name(mach_hdr *header, char *sect_name) {
    load_cmd *loadCmd;
    sgmt_cmd *sgmtCmd;
    sect_cmd *sectCmd;

    loadCmd = (zz_ptr_t)header + sizeof(mach_hdr);
    zz_size_t i;
    zz_size_t j;
    for (i = 0; i < header->ncmds; i++, loadCmd = (zz_ptr_t)loadCmd + loadCmd->cmdsize) {
        if (loadCmd->cmd == LC_SGMT) {
            sgmtCmd = (sgmt_cmd *)loadCmd;
            sectCmd = (sect_cmd *)((zz_ptr_t)sgmtCmd + sizeof(sgmt_cmd));
            for (j = 0; j < sgmtCmd->nsects; j++, sectCmd = (zz_ptr_t)sectCmd + sizeof(sect_cmd)) {
                if (!strcmp(sectCmd->sectname, sect_name)) {
                    return sectCmd;
                }
            }
        }
    }
    return NULL;
}

load_cmd *zz_macho_get_load_command_via_cmd(mach_hdr *header, uint32_t cmd) {
    load_cmd *loadCmd;
    sgmt_cmd *sgmtCmd;
    sect_cmd *sectCmd;

    loadCmd = (zz_ptr_t)header + sizeof(mach_hdr);
    for (int i = 0; i < header->ncmds; i++, loadCmd = (zz_ptr_t)loadCmd + loadCmd->cmdsize) {
        if (loadCmd->cmd == cmd) {
            return loadCmd;
        }
    }
    return NULL;
}

zz_ptr_t zz_macho_get_symbol_via_name(mach_hdr *header, const char *name) {
    sgmt_cmd *sgmtCmd             = zz_macho_get_segment_via_name((mach_hdr *)header, (char *)"__TEXT");
    sgmt_cmd *sgmtCmdLinkedit     = zz_macho_get_segment_via_name((mach_hdr *)header, (char *)"__LINKEDIT");
    zz_size_t slide               = (zz_addr_t)header - (zz_addr_t)sgmtCmd->vmaddr;
    zz_size_t linkEditBase        = sgmtCmdLinkedit->vmaddr - sgmtCmdLinkedit->fileoff + slide;
    struct symtab_command *symtab = (struct symtab_command *)zz_macho_get_load_command_via_cmd(header, LC_SYMTAB);

    char *sym_str_table = (char *)linkEditBase + symtab->stroff;
    nlist_ *sym_table   = (nlist_ *)(linkEditBase + symtab->symoff);

    for (int i = 0; i < symtab->nsyms; i++) {
        if (sym_table[i].n_value && !strcmp(name, &sym_str_table[sym_table[i].n_un.n_strx])) {
            return (void *)(uint64_t)(sym_table[i].n_value + slide);
        }
    }
    return 0;
}

zz_ptr_t zz_macho_get_section_address_via_name(mach_hdr *header, char *sect_name) {
    load_cmd *loadCmd;
    sgmt_cmd *sgmtCmd;
    sect_cmd *sectCmd;
    zz_size_t slide, linkEditBase;

    loadCmd = (zz_ptr_t)header + sizeof(mach_hdr);
    for (int i = 0; i < header->ncmds; i++, loadCmd = (zz_ptr_t)loadCmd + loadCmd->cmdsize) {
        if (loadCmd->cmd == LC_SGMT) {
            sgmtCmd = (sgmt_cmd *)loadCmd;
            if ((sgmtCmd->fileoff == 0) && (sgmtCmd->filesize != 0)) {
                slide = (uintptr_t)header - sgmtCmd->vmaddr;
            }
            if (strcmp(sgmtCmd->segname, "__LINKEDIT") == 0) {
                linkEditBase = sgmtCmd->vmaddr - sgmtCmd->fileoff + slide;
            }
            sectCmd = (sect_cmd *)((zz_ptr_t)sgmtCmd + sizeof(sgmt_cmd));
            for (int j = 0; j < sgmtCmd->nsects; j++, sectCmd = (zz_ptr_t)sectCmd + sizeof(sect_cmd)) {
                if (!strcmp(sectCmd->sectname, sect_name)) {
                    return (zz_ptr_t)(sectCmd->addr + slide);
                }
            }
        }
    }
    return NULL;
}
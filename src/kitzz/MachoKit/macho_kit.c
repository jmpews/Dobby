#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <mach/task_info.h>

#include "MachoKit/macho_kit.h"

#if 0
#ifdef __LP64__
#define mach_hdr struct mach_header_64
#define sgmt_cmd struct segment_command_64
#define sect_cmd struct section_64
#define nlist_ struct nlist_64
#define LC_SGMT LC_SEGMENT_64
#define MH_MAGIC_ MH_MAGIC_64
#else
#define mach_hdr struct mach_header
#define sgmt_cmd struct segment_command
#define sect_cmd struct section
#define nlist_ struct nlist
#define LC_SGMT LC_SEGMENT
#define MH_MAGIC_ MH_MAGIC
#endif
#define load_cmd struct load_command
#endif

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
    if (zz_vm_read_data_via_task(task, infoData.all_image_info_addr, allImageInfos,
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

struct segment_command_64 *zz_macho_get_segment_64_via_name(struct mach_header_64 *header, char *segment_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;

    load_cmd = (zz_ptr_t)header + sizeof(struct mach_header_64);
    zz_size_t i;
    for (i = 0; i < header->ncmds; i++, load_cmd = (zz_ptr_t)load_cmd + load_cmd->cmdsize) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            if (!strcmp(seg_cmd_64->segname, segment_name)) {
                return seg_cmd_64;
            }
        }
    }
    return NULL;
}

struct section_64 *zz_macho_get_section_64_via_name(struct mach_header_64 *header, char *sect_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;

    load_cmd = (zz_ptr_t)header + sizeof(struct mach_header_64);
    zz_size_t i;
    zz_size_t j;
    for (i = 0; i < header->ncmds; i++, load_cmd = (zz_ptr_t)load_cmd + load_cmd->cmdsize) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            sect_64    = (struct section_64 *)((zz_ptr_t)seg_cmd_64 + sizeof(struct segment_command_64));
            for (j = 0; j < seg_cmd_64->nsects; j++, sect_64 = (zz_ptr_t)sect_64 + sizeof(struct section_64)) {
                if (!strcmp(sect_64->sectname, sect_name)) {
                    return sect_64;
                }
            }
        }
    }
    return NULL;
}

struct load_command *zz_macho_get_load_command_via_cmd(struct mach_header_64 *header, uint32_t cmd) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    zz_size_t i;

    load_cmd = (zz_ptr_t)header + sizeof(struct mach_header_64);
    for (i = 0; i < header->ncmds; i++, load_cmd = (zz_ptr_t)load_cmd + load_cmd->cmdsize) {
        if (load_cmd->cmd == cmd) {
            return load_cmd;
        }
    }
    return NULL;
}

zz_ptr_t zz_macho_get_symbol_via_name(struct mach_header_64 *header, const char *name) {

    struct segment_command_64 *seg_cmd_64 =
        zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
    struct segment_command_64 *seg_cmd_64_linkedit =
        zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__LINKEDIT");
    zz_size_t slide               = (zz_addr_t)header - (zz_addr_t)seg_cmd_64->vmaddr;
    zz_size_t linkEditBase        = seg_cmd_64_linkedit->vmaddr - seg_cmd_64_linkedit->fileoff + slide;
    struct symtab_command *symtab = (struct symtab_command *)zz_macho_get_load_command_via_cmd(header, LC_SYMTAB);

    char *sym_str_table        = (char *)linkEditBase + symtab->stroff;
    struct nlist_64 *sym_table = (struct nlist_64 *)(linkEditBase + symtab->symoff);

    int i;
    for (i = 0; i < symtab->nsyms; i++) {
        if (sym_table[i].n_value && !strcmp(name, &sym_str_table[sym_table[i].n_un.n_strx])) {
            return (void *)(uint64_t)(sym_table[i].n_value + slide);
        }
    }
    return 0;
}

zz_ptr_t zz_macho_get_section_64_address_via_name(struct mach_header_64 *header, char *sect_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    zz_size_t slide, linkEditBase;
    zz_size_t i, j;

    load_cmd = (zz_ptr_t)header + sizeof(struct mach_header_64);
    for (i = 0; i < header->ncmds; i++, load_cmd = (zz_ptr_t)load_cmd + load_cmd->cmdsize) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            if ((seg_cmd_64->fileoff == 0) && (seg_cmd_64->filesize != 0)) {
                slide = (uintptr_t)header - seg_cmd_64->vmaddr;
            }
            if (strcmp(seg_cmd_64->segname, "__LINKEDIT") == 0) {
                linkEditBase = seg_cmd_64->vmaddr - seg_cmd_64->fileoff + slide;
            }
            sect_64 = (struct section_64 *)((zz_ptr_t)seg_cmd_64 + sizeof(struct segment_command_64));
            for (j = 0; j < seg_cmd_64->nsects; j++, sect_64 = (zz_ptr_t)sect_64 + sizeof(struct section_64)) {
                if (!strcmp(sect_64->sectname, sect_name)) {
                    return (zz_ptr_t)(sect_64->addr + slide);
                }
            }
        }
    }
    return NULL;
}

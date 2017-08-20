
#include <mach-o/dyld_images.h>
#include <mach/task_info.h>

#include "../common/debugbreak.h"
#include "../darwin/memory-utils-darwin.h"
#include "macho-utils-darwin.h"

// get dyld load address by task_info, TASK_DYLD_INFO
zpointer zz_macho_get_dyld_load_address_via_task(task_t task) {
  // http://stackoverflow.com/questions/4309117/determining-programmatically-what-modules-are-loaded-in-another-process-os-x
  kern_return_t kr;
  task_flavor_t flavor = TASK_DYLD_INFO;
  task_dyld_info_data_t infoData;
  mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
  kr = task_info(task, flavor, (task_info_t)&infoData, &task_info_outCnt);
  if (kr != KERN_SUCCESS) {
    KR_ERROR(kr);
    return 0;
  }
  struct dyld_all_image_infos *allImageInfos =
      (struct dyld_all_image_infos *)infoData.all_image_info_addr;
  allImageInfos = (struct dyld_all_image_infos *)malloc(
      sizeof(struct dyld_all_image_infos));
  if (zz_vm_read_data_via_task(task, infoData.all_image_info_addr,
                               allImageInfos,
                               sizeof(struct dyld_all_image_infos))) {
    return (zpointer)(allImageInfos->dyldImageLoadAddress);
  } else {
    return NULL;
  }
}

task_t zz_darwin_get_task_via_pid(int pid) {
  task_t t;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
  if (kr != KERN_SUCCESS) {
    KR_ERROR(kr);
    return 0;
  }
  return t;
}

struct segment_command_64 *
zz_macho_get_segment_64_via_name(struct mach_header_64 *header,
                                 char *segment_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    
    load_cmd = (zpointer)header + sizeof(struct mach_header_64);
    for (zsize i = 0; i < header->ncmds;
         i++, load_cmd = (zpointer)load_cmd + load_cmd->cmdsize) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            if(!strcmp(seg_cmd_64->segname, segment_name)) {
                return seg_cmd_64;
            }
        }
    }
    return NULL;
}

struct section_64 *
zz_macho_get_section_64_via_name(struct mach_header_64 *header,
                                 char *sect_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    
    load_cmd = (zpointer)header + sizeof(struct mach_header_64);
    for (zsize i = 0; i < header->ncmds;
         i++, load_cmd = (zpointer)load_cmd + load_cmd->cmdsize) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            sect_64 = (struct section_64 *)((zpointer)seg_cmd_64 +
                                            sizeof(struct segment_command_64));
            for (zsize j = 0; j < seg_cmd_64->nsects;
                 j++, sect_64 = (zpointer)sect_64 + sizeof(struct section_64)) {
                if (!strcmp(sect_64->sectname, sect_name)) {
                    return sect_64;
                }
            }
        }
    }
    return NULL;
}

zpointer zz_macho_get_section_64_address_via_name(struct mach_header_64 *header,
                                 char *sect_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    zsize slide, linkEditBase;

    load_cmd = (zpointer)header + sizeof(struct mach_header_64);
    for (zsize i = 0; i < header->ncmds;
         i++, load_cmd = (zpointer)load_cmd + load_cmd->cmdsize) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            if ( (seg_cmd_64->fileoff == 0) && (seg_cmd_64->filesize != 0) ) {
                slide = (uintptr_t)header - seg_cmd_64->vmaddr;
            }
            if ( strcmp(seg_cmd_64->segname, "__LINKEDIT") == 0 ) {
                linkEditBase = seg_cmd_64->vmaddr - seg_cmd_64->fileoff + slide;
            }
            sect_64 = (struct section_64 *)((zpointer)seg_cmd_64 +
                                            sizeof(struct segment_command_64));
            for (zsize j = 0; j < seg_cmd_64->nsects;
                j++, sect_64 = (zpointer)sect_64 + sizeof(struct section_64)) {
                if (!strcmp(sect_64->sectname, sect_name)) {
                    return (zpointer)(sect_64->addr + slide);
                }
            }
        }
    }
    return NULL;
}
#include "InterfaceInternal.h"

extern void _dyld_register_func_for_add_image(void (*func)(const struct mach_header *mh, intptr_t vmaddr_slide));

typedef uint64_t addr_t;

void *getSegmentContent(mach_header_t *header, char *segName) {
  struct load_command *load_cmd;
  segment_command_t *seg_cmd;
  section_t *sect;
  // initialize the segment info
  load_cmd = (struct load_command *)((addr_t)header + sizeof(mach_header_t));
  for (int i = 0; i < header->ncmds; i++, load_cmd = (struct load_command *)((addr_t)load_cmd + load_cmd->cmdsize)) {
    if (load_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      seg_cmd = (segment_command_t *)load_cmd;
      if (!strcmp(seg_cmd->segname, segName)) {
        size_t fileoff = seg_cmd->fileoff;
        void *content  = (void *)((addr_t)header + fileoff);
        return content;
      }
    }
  }
  return NULL;
}

void rebase_stub(const struct mach_header *mh, intptr_t vmaddr_slide) {
  void *zDATAContent = getSegmentContent((mach_header_t *)mh, "__zDATA");
  if (zDATAContent) {
    InterceptorStatic *interceptor = (InterceptorStatic *)zDATAContent;
    if (interceptor->this_ && ((addr_t)interceptor->this_ != (addr_t)zDATAContent)) {
      // set interceptor initialized flag.
      interceptor->this_ == (uint64_t)zDATAContent;
      
      // iterate all entry
      for (int i = 0; i < interceptor->count; i++) {
        interceptor->entry[i] += vmaddr_slide;
        HookEntryStatic *entry = reinterpret_cast<HookEntryStatic *>(interceptor->entry[i]);
        entry->relocated_origin_function += vmaddr_slide;
        entry->trampoline_target_stub = (uint64_t *)((uint64_t)entry->trampoline_target_stub + vmaddr_slide);
        *entry->trampoline_target_stub = entry->relocated_origin_function;
      }
    }
  }
}

__attribute__((constructor))
void _rebase_process() {
  _dyld_register_func_for_add_image(rebase_stub);
}

#ifndef memory_allocator_h
#define memory_allocator_h

#include "core.h"
#include "hookzz.h"
#include "std_kit/std_list.h"
#include <stdint.h>

// memory permission prot
#define PROT_RW_ (1 | 2)
#define PROT_R_X (1 | 4)

typedef struct _CodeSlice {
  void *data;
  int size;
} CodeSlice;

typedef struct _CodeCave {
  int size;
  void *backup;
  void *address;
} CodeCave;

typedef struct _MemoryBlock {
  int prot; // memory permission
  int size;
  void *address;
} MemoryBlock;

typedef struct _FreeMemoryBlock {
  int prot; // memory permission
  int total_size;
  int used_size;
  void *address;
} FreeMemoryBlock;

typedef struct _memory_manager_t {
  bool is_support_rx_memory;
  list_t *code_caves;
  list_t *process_memory_layout;
  list_t *free_memory_blocks;
} memory_manager_t;

#define memory_manager_cclass(member) cclass(memory_manager, member)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

memory_manager_t *memory_manager_cclass(shared_instance)();

PLATFORM_API int memory_manager_cclass(get_page_size)();

PLATFORM_API void memory_manager_cclass(set_page_permission)(void *page_address, int prot, int n);

PLATFORM_API bool memory_manager_cclass(is_support_allocate_rx_memory)(memory_manager_t *self);

PLATFORM_API void *memory_manager_cclass(allocate_page)(memory_manager_t *self, int prot, int n);

PLATFORM_API void memory_manager_cclass(patch_code)(memory_manager_t *self, void *dest, void *src, int count);

PLATFORM_API void memory_manager_cclass(get_process_memory_layout)(memory_manager_t *self);

CodeCave *memory_manager_cclass(search_code_cave)(memory_manager_t *self, void *address, int range, int size);

CodeSlice *memory_manager_cclass(allocate_code_slice)(memory_manager_t *self, int size);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
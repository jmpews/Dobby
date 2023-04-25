#pragma once

#include "dobby/common.h"
#include "MemoryAllocator/MemoryAllocator.h"

typedef enum { kFunctionInlineHook, kInstructionInstrument } InterceptRoutingType;

struct InterceptRouting;
struct Interceptor {
  struct Entry {
    uint32_t id = 0;

    struct {
      bool arm_thumb_mode;
    } features;

    addr_t fake_func_addr;
    dobby_instrument_callback_t pre_handler;
    dobby_instrument_callback_t post_handler;

    addr_t addr;

    MemBlock patched;
    MemBlock relocated;

    uint8_t *origin_code_buffer = 0;

    Entry(addr_t addr) {
      this->addr = addr;
    }

    ~Entry() {
      if (origin_code_buffer) {
        free(origin_code_buffer);
      }
    }

    void set_arm_thumb_feature(bool thumb) {
      features.arm_thumb_mode = thumb;
    }
  };

  tinystl::vector<Entry *> entries;

  static Interceptor *Shared();

  Entry *find(addr_t addr) {
    for (auto *entry : entries) {
      if (entry->patched.addr() == addr) {
        return entry;
      }
    }
    return nullptr;
  }

  Entry *remove(addr_t addr) {
    for (auto iter = entries.begin(); iter != entries.end(); iter++) {
      if ((*iter)->patched.addr() == addr) {
        Entry *entry = *iter;
        entries.erase(iter);
        return entry;
      }
    }
    return nullptr;
  }

  void add(Entry *entry) {
    entries.push_back(entry);
  }

  const Entry *get(int i) {
    return entries[i];
  }

  int count() const {
    return entries.size();
  }
};

inline static Interceptor gInterceptor;

inline Interceptor *Interceptor::Shared() {
  return &gInterceptor;
}
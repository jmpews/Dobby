#ifndef ZZ_MODULES_ASSEMBLER_ASSEMBLER_H_
#define ZZ_MODULES_ASSEMBLER_ASSEMBLER_H_

#include "vm_core/base/code-buffer.h"
#include "vm_core/objects/objects.h"
#include "vm_core/objects/code.h"

#include <iostream>
#include <vector>

namespace zz {
class Label {
public:
  Label() : pos_(0), near_link_pos_(0) {}

  ~Label() {}

public:
  bool is_bound() const { return pos_ < 0; }
  bool is_unused() const { return pos_ == 0 && near_link_pos_ == 0; }
  bool is_linked() const { return pos_ > 0; }
  bool is_near_linked() const { return near_link_pos_ > 0; }
  int pos() const {
    if (pos_ < 0)
      return -pos_ - 1;
    if (pos_ > 0)
      return pos_ - 1;
    return 0;
  }
  void bind_to(int pos) { pos_ = -pos - 1; }
  void link_to(int pos) {
    // for special condition: link_to(0)
    pos_ = pos + 1;
  }

private:
  // pos_: "< 0", indicate the Label is Binded, "> 0", indicate the Label is Linked, "= 0" indicate the Label is iter-terminal or unused
  int pos_;
  int near_link_pos_;
};

class ObjectPool {
public:
  intptr_t AddObject(const Object &obj);

  intptr_t FindObject(const Object &obj);

private:
  std::vector<Object *> object_pool_;
};

class ExternalReference {
public:
  explicit ExternalReference(void *address) : address_(address) {}

  const inline void *address() { return address_; }

private:
  const void *address_;
};

// =====

class AssemblerBase {
public:
  AssemblerBase() { DLOG("[*] Assembler buffer at %p\n", buffer_.RawBuffer()); }

  int pc_offset() const { return buffer_.Size(); }

  // =====

  size_t CodeSize() { return buffer_.Size(); }

  CodeBuffer *GetCodeBuffer() { return &buffer_; }

  virtual Code *GetCode() = 0;

  // =====

  virtual void CommitRealize(void *address) = 0;

  // =====

  static void FlushICache(void *start, size_t size);
  static void FlushICache(uintptr_t start, size_t size) { return FlushICache(reinterpret_cast<void *>(start), size); }

  // =====

protected:
  CodeBuffer buffer_;
  ObjectPool *object_pool_;
};

} // namespace zz

#include "vm_core/globals.h"
#if TARGET_ARCH_ARM
#include "vm_core/modules/assembler/assembler-arm.h"
#elif TARGET_ARCH_ARM64
#include "vm_core/modules/assembler/assembler-arm64.h"
#endif

#endif

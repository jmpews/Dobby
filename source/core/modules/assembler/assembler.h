#ifndef CORE_ASSEMBLER_H
#define CORE_ASSEMBLER_H

#include "ExecMemory/CodeBuffer/CodeBufferBase.h"

class CodeBuffer;

namespace zz {

class Label {
public:
  Label() : pos_(0), near_link_pos_(0) {
  }

  ~Label() {
  }

public:
  bool is_bound() const;

  bool is_unused() const;

  bool is_linked() const;

  bool is_near_linked() const;

  int pos() const;

  void bind_to(int pos);

  void link_to(int pos);

private:
  // pos_: "< 0", indicate the Label is Binded, "> 0", indicate the Label is Linked, "= 0" indicate the Label is
  // iter-terminal or unused
  int pos_;
  int near_link_pos_;
};

#if 0
class LiteObjectPool {
public:
  intptr_t AddObject(const LiteObject &obj);

  intptr_t FindObject(const LiteObject &obj);

private:
  std::vector<LiteObject *> object_pool_;
};
#endif

class ExternalReference {
public:
  explicit ExternalReference(void *address) : address_(address) {
  }

  const void *address();

private:
  const void *address_;
};

class AssemblerBase {
public:
  AssemblerBase(void *address);

public:
  int pc_offset() const;

  CodeBuffer *GetCodeBuffer();

  virtual void CommitRealizeAddress(void *address);

  virtual void *GetRealizeAddress();

  static void FlushICache(addr_t start, int size);

  static void FlushICache(addr_t start, addr_t end);

private:
  AssemblerBase() {
  }

protected:
  CodeBuffer *buffer_;

  void *realized_address_;
};

} // namespace zz

#if 0
#include "globals.h"
#if TARGET_ARCH_ARM
#include "core/modules/assembler/assembler-arm.h"
#elif TARGET_ARCH_ARM64
#include "core/modules/assembler/assembler-arm64.h"
#elif TARGET_ARCH_X64
#include "core/modules/assembler/assembler-x64.h"
#include "ExecMemory/CodeBuffer/code-buffer-x64.h"
#else
#error "unsupported architecture"
#endif
#endif

#endif

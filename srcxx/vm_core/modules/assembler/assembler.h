#ifndef ZZ_MODULES_ASSEMBLER_ASSEMBLER_H_
#define ZZ_MODULES_ASSEMBLER_ASSEMBLER_H_

#include "vm_core/base/code-buffer.h"
#include "vm_core/objects/objects.h"

namespace zz {

class Label {
public:
  Label() : location_() {
  }

  ~Label() {
  }

public:
  bool is_bound() const {
    return pos_ < 0;
  }
  bool is_unused() const {
    return pos_ == 0 && near_link_pos_ == 0;
  }
  bool is_linked() const {
    return pos_ > 0;
  }
  bool is_near_linked() const {
    return near_link_pos_ > 0;
  }

  int pos() const {
    if (pos_ < 0)
      return -pos_ - 1;
    if (pos_ > 0)
      return pos_ - 1;
    UNREACHABLE();
  }

private:
  void bind_to(int pos) {
    pos_ = -pos - 1;
  }

  void link_to(int pos) {
    pos_ = pos + 1;
  }

private:
  int pos_;
};

class ObjectPool {
public:
  intptr_t AddObject(const Object &obj);

  intptr_t FindObject(const Object &obj);

private:
  std::vector<Object *> object_pool_;
}

class AssemblerBase {
public:
  int pc_offset() const {
    return buffer_.Size();
  }

  static void FlushICache(void *start, size_t size);
  static void FlushICache(Address start, size_t size) {
    return FlushICache(reinterpret_cast<void *>(start), size);
  }

protected:
  CodeBuffer *buffer_;
  ObjectPool *object_pool_;
};

} // namespace zz

#endif
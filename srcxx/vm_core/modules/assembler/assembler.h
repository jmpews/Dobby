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

private:
  int location_;
};


class ObjectPool {
  public:

  intptr_t AddObject(const Object& obj);

  intptr_t FindObject(const Object& obj);
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
  std::vector<Object *> object_pool;
};

} // namespace zz

#endif
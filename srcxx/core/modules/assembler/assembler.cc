#include <iostream>
#include <vector>
#include "core/modules/assembler.h"

namespace zz {

bool Label::is_bound() const {
  return pos_ < 0;
}
bool Label::is_unused() const {
  return pos_ == 0 && near_link_pos_ == 0;
}
bool Label::is_linked() const {
  return pos_ > 0;
}
bool Label::is_near_linked() const {
  return near_link_pos_ > 0;
}
int Label::pos() const {
  if (pos_ < 0)
    return -pos_ - 1;
  if (pos_ > 0)
    return pos_ - 1;
  return 0;
}
void Label::bind_to(int pos) {
  pos_ = -pos - 1;
}
void Label::link_to(int pos) {
  // for special condition: link_to(0)
  pos_ = pos + 1;
}

const inline void *ExternalReference::address() {
  return address_;
}

AssemblerBase::AssemblerBase() {
  DLOG("[*] Assembler buffer at %p\n", buffer_.RawBuffer());
}

int AssemblerBase::pc_offset() const {
  return buffer_.Size();
}

size_t AssemblerBase::CodeSize() {
  return buffer_.Size();
}

CodeBuffer *AssemblerBase::GetCodeBuffer() {
  return &buffer_;
}

static void AssemblerBase::FlushICache(void *start, size_t size);

static void AssemblerBase::FlushICache(uintptr_t start, size_t size) {
  return FlushICache(reinterpret_cast<void *>(start), size);
}

} // namespace zz

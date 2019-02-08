#include "core/modules/assembler/assembler.h"
#include "logging/logging.h"

namespace zz {

// ===== Label =====

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

// ===== ExternalReferencej =====

const void *ExternalReference::address() {
  return address_;
}

// ===== AssemblerBase =====

AssemblerBase::AssemblerBase() {
  buffer_ = new CodeBuffer;
  buffer_->initWithCapacity(32);
  DLOG("[*] Assembler buffer at %p\n", buffer_->getRawBuffer());
}

int AssemblerBase::pc_offset() const {
  return buffer_->getSize();
}

CodeBuffer *AssemblerBase::GetCodeBuffer() {
  return buffer_;
}

void AssemblerBase::CommitRealizeAddress(void *address) {
  realized_address_ = address;
}

void *AssemblerBase::GetRealizeAddress() {
  return realized_address_;
}

void AssemblerBase::FlushICache(void *start, size_t size) {
}

void AssemblerBase::FlushICache(uintptr_t start, uintptr_t end) {
}

} // namespace zz

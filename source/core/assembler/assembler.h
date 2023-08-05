#pragma once

#include "dobby/common.h"
#include "pseudo_label.h"

namespace zz {
struct ExternalReference {
  void *address;

  explicit ExternalReference(void *address) : address(address) {
    address = pac_strip(address);
  }
};

struct AssemblerBase {
  addr_t fixed_addr;
  CodeMemBuffer code_buffer_;
  stl::vector<RelocDataLabel *> data_labels;

  explicit AssemblerBase(addr_t fixed_addr) {
    this->fixed_addr = fixed_addr;
  }

  ~AssemblerBase() = default;

  size_t pc_offset() {
    return code_buffer_.size();
  }

  void set_fixed_addr(addr_t in_fixed_addr) {
    this->fixed_addr = in_fixed_addr;
  }

  CodeMemBuffer *code_buffer() {
    return &code_buffer_;
  }

  // --- label

  RelocDataLabel *createDataLabel(uint64_t data) {
    auto data_label = new RelocDataLabel(data);
    data_labels.push_back(data_label);
    return data_label;
  }

  void bindLabel(PseudoLabel *label) {
    label->bind_to(pc_offset());
    if (label->has_confused_instructions()) {
      label->link_confused_instructions(&code_buffer_);
    }
  }

  void relocDataLabels() {
    for (auto *data_label : data_labels) {
      bindLabel(data_label);
      code_buffer_.emit(data_label->data_, data_label->data_size_);
    }
  }
};

} // namespace zz
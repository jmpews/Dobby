#pragma once

#include "MemoryAllocator/CodeMemBuffer.h"

struct Label {
  addr_t pos;
};

struct PseudoLabel : Label {
  struct ref_inst_t {
    int link_type;
    uintptr_t inst_offset;
    explicit ref_inst_t(int link_type, size_t inst_offset) : link_type(link_type), inst_offset(inst_offset) {
    }

    int type() {
      return link_type;
    }

    uintptr_t offset() {
      return inst_offset;
    }
  };

  CodeMemBuffer *code_buffer;
  stl::vector<ref_inst_t> ref_insts;

  PseudoLabel() : PseudoLabel(0) {
  }

  PseudoLabel(addr_t pos) {
    bind_to(pos);
  }

  void bind_to(addr_t pos) {
    this->pos = pos;
  }

  bool has_confused_instructions() {
    return !ref_insts.empty();
  }

  void link_confused_instructions(CodeMemBuffer *buffer);

  void link_to(int link_type, uint32_t pc_offset) {
    ref_inst_t insn(link_type, pc_offset);
    ref_insts.push_back(insn);
  }
};

struct RelocDataLabel : PseudoLabel {
  uint8_t data_[8];
  uint8_t data_size_;

  RelocDataLabel() {
    data_size_ = 0;
  }

  template <typename T> RelocDataLabel(T data) {
    *(T *)data_ = data;
    data_size_ = sizeof(T);
  }

  template <typename T> T data() {
    return *(T *)data_;
  }

  template <typename T> void fixupData(T value) {
    *(T *)data_ = value;
  }
};
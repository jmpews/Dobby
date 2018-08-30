#ifndef ZZ_MODULES_ASSEMBLER_ASSEMBLER_H_
#define ZZ_MODULES_ASSEMBLER_ASSEMBLER_H_

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

class PseudoLabel : public Label {
  enum PseudoLabelType { kLdrPseudoLabel };

  typedef struct _PseudoLabelInstruction {
    int position_;
    PseudoLabelType type_;
  } PseudoLabelInstruction;

public:
  bool has_confused_instructions() {
    return instructions_.size() > 0;
  }
  void link_confused_instructions(CodeBuffer *buffer = nullptr) {
    if (buffer)
      buffer_ = buffer;

    int32_t offset       = instruction->position_ - this->position_;
    const int32_t inst32 = buffer_.Load32(instruction->position);
    for (auto instruction : instructions_) {
      switch (instruction.type_) {
      case kLdrPseudoLabel: {
        const int32_t encoded = (inst32 & 0xfff) | offset;
      } break;
      default:
        break;
      }
      buffer_.Store32(instrcution->position, encoed);
    }
  };

private:
  // From a design perspective, these fix-function write as callback, maybe beeter.
  void FixLdr(PseudoLabelInstruction *instruction){
      // dummy
  };

private:
  CodeBuffer *buffer_;
  std::vector<PseudoLabelInstruction> instructions_;
};

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
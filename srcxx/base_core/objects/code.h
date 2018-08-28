#ifndef ZZ_BASE_OBJECTS_CODE
#define ZZ_BASE_OBJECTS_CODE

#include "base_core/objects/objects.h"
#include "base_core/platform/platform.h"

using namespace zz;

class RawCode : public Object {};

class Code : public Object {
  inline int raw_instruction_size() const;
  inline void set_raw_instruction_size(int value);

  inline int InstructionSize() const;

  RawCode *FinalizeCode() {
  }

  void Commit() {
    Platform::SetPermission(0, 0, 0);
  }
};

#endif
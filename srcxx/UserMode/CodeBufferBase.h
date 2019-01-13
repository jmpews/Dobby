#ifndef ZZ_CODE_BUFFER_H_
#define ZZ_CODE_BUFFER_H_

#include "stdcxx/LiteMutableBuffer.h"

class CodeBuffer : LiteMutableBuffer {

public:
  template <typename T> T Load(int offset);

  template <typename T> void Store(int offset, T value);

  template <typename T> void Emit(T value);

  void EmitObject(LiteObject *object);
};

#endif
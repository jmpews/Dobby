#ifndef ZZ_BASE_OBJECTS_CODE
#define ZZ_BASE_OBJECTS_CODE

#include "src/base/objects/objects.h"

#include "src/platform/platform.h"

using namespace zz;

class RawCode : public Object {

};

class Code : public Object {
    RawCode* FinalizeCode() {

    }
    void Commit() {
        Platform::SetPermission(0, 0, 0);
    }
};

#endif
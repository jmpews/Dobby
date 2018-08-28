#ifndef ZZ_OBJECTS_H
#define ZZ_OBJECTS_H

/* ----

 - Object
 -- HeapObject
 -- Code
 
---- */

class Object {
public:
  SetEmbeddedBlob(uint8_t *blob, uint32_t blob_size);

private:
  const uint8_t *embedded_blob_ = nullptr;
  uint32_t embedded_blob_size_  = 0;
};

class RawObject {};

class HeapObject : public Object {};

#endif
/* ----

 - Object
 -- HeapObject
 -- Code
 
---- */

class Object {
public:
  void SetEmbeddedBlob(uint8_t *blob, uint32_t blob_size){};

private:
  const uint8_t *embedded_blob_ = nullptr;
  uint32_t embedded_blob_size_  = 0;
};

class RawObject {};

class HeapObject : public Object {};

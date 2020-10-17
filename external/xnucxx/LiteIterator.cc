#include "xnucxx/LiteIterator.h"

#include "xnucxx/LiteCollection.h"

void LiteCollectionIterator::reset() {
  this->collection->initIterator(this->innerIterator);
  return;
}

bool LiteCollectionIterator::initWithCollection(const LiteCollection *collection) {
  this->collection = (LiteCollection *)collection;

  int *ndxPtr         = (int *)LiteMemOpt::alloc(sizeof(int));
  this->innerIterator = (void *)ndxPtr;
  this->collection->initIterator(this->innerIterator);
  return true;
}

LiteCollectionIterator *LiteCollectionIterator::withCollection(const LiteCollection *collection) {
  LiteCollectionIterator *iter = new LiteCollectionIterator;
  iter->initWithCollection(collection);
  return iter;
}

LiteObject *LiteCollectionIterator::getNextObject() {
  LiteObject *retObj;
  collection->getNextObjectForIterator(this->innerIterator, &retObj);
  return retObj;
}

void LiteCollectionIterator::release() {
  LiteMemOpt::free(this->innerIterator, sizeof(void *));
}

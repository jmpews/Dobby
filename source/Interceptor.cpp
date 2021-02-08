#include "Interceptor.h"

#include "dobby_internal.h"

Interceptor *      Interceptor::priv_interceptor_ = nullptr;

Interceptor *Interceptor::SharedInstance() { 
  if (Interceptor::priv_interceptor_ == NULL) {
    Interceptor::priv_interceptor_          = new Interceptor();
    INIT_LIST_HEAD(&Interceptor::priv_interceptor_->hook_entry_list_);
  }
  return Interceptor::priv_interceptor_;
}

HookEntryListNode *Interceptor::FindHookEntryNode(void *address) {
  HookEntry *entry = NULL;

  struct list_head *node  = NULL;
  for (node = hook_entry_list_.next;  node != &hook_entry_list_; node = node->next) {
    if(((HookEntryListNode *)node)->info.target_address == address) {
      return (HookEntryListNode *)node;
    }
  }

  return NULL;
}

HookEntry *Interceptor::FindHookEntry(void *address) {
  HookEntryListNode *node = NULL;
  node = FindHookEntryNode(address);
  if(node)
    return &node->info;

  return NULL;
}



void Interceptor::AddHookEntry(HookEntry *entry) {
  HookEntryListNode *node = new HookEntryListNode ;
  node->info = *entry;
  list_add((struct list_head *)node, &hook_entry_list_);
}

void Interceptor::RemoveHookEntry(void *address) {
  HookEntryListNode *node = NULL;
  node = FindHookEntryNode(address);
  if(node) {
    list_del((struct list_head *)node);
  }
}

int Interceptor::GetHookEntryCount() {
  int count = 0;

  struct list_head *node  = &hook_entry_list_;
  while((node = node->next) != &hook_entry_list_) {
    count += 1;
  }
  return count;
}

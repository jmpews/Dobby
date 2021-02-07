#include "Interceptor.h"

#include "dobby_internal.h"

Interceptor *      Interceptor::priv_interceptor_ = nullptr;

Interceptor *Interceptor::SharedInstance() {
  if (Interceptor::priv_interceptor_ == NULL) {
    Interceptor::priv_interceptor_          = new Interceptor();
  }
  return Interceptor::priv_interceptor_;
}

HookEntryListNode *Interceptor::FindHookEntryNode(void *address) {
  HookEntry *entry = NULL;

  struct list_head *node  = NULL;
  for (node = hook_entry_list_->next;  node != hook_entry_list_; node = node->next) {
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
  list_add(hook_entry_list_, (struct list_head *)node);
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

  struct list_head *node  = hook_entry_list_;
  while((node = hook_entry_list_->next)) {
    count += 1;
  }
  return count;
}
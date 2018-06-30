#include "closure_bridge.h"
#include "memory_manager.h"

ClosureBridge *gClosureBridge = NULL;
ClosureBridge *ClosureBridgeCClass(SharedInstance)() {
    if (gClosureBridge == NULL) {
        gClosureBridge                    = SAFE_MALLOC_TYPE(ClosureBridge);
        gClosureBridge->bridge_infos      = list_new();
        gClosureBridge->trampoline_tables = list_new();
    }
    return gClosureBridge;
}

ClosureBridgeTrampolineTable *ClosureBridgeCClass(AllocateClosureBridgeTrampolineTable)(ClosureBridge *self) {
    void *mmap_page = NULL;
    long page_size  = 0;

    memory_manager_t *memory_manager = memory_manager_cclass(shared_instance)();
    void *page_ptr                   = memory_manager_cclass(allocate_page)(memory_manager, PROT_R_X, 1);

    ClosureBridgeTrampolineTable *table = SAFE_MALLOC_TYPE(ClosureBridgeTrampolineTable);

    ClosureBridgeCClass(InitializeTablePage)(table, page_ptr);

    list_rpush(self->trampoline_tables, list_node_new(table));

    return table;
}

ClosureBridgeInfo *ClosureBridgeCClass(AllocateClosureBridge)(ClosureBridge *self, void *user_data, void *user_code) {
    ClosureBridgeInfo *cb_info          = NULL;
    ClosureBridgeTrampolineTable *table = NULL;

    list_iterator_t *it = list_iterator_new(self->trampoline_tables, LIST_HEAD);
    for (int i = 0; i < self->trampoline_tables->len; i++) {
        ClosureBridgeTrampolineTable *tmp_table =
            (ClosureBridgeTrampolineTable *)(list_at(self->trampoline_tables, i)->val);
        if (tmp_table->free_count > 0) {
            table = tmp_table;
        }
    }

    if (!table) {
        table = ClosureBridgeCClass(AllocateClosureBridgeTrampolineTable)(self);
    }

    cb_info = SAFE_MALLOC_TYPE(ClosureBridgeInfo);
    ClosureBridgeCClass(InitializeClosureBridgeInfo)(table, cb_info, user_data, user_code);

    list_rpush(self->bridge_infos, list_node_new(cb_info));
    return cb_info;
}

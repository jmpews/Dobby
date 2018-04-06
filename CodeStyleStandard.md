## 缩写规范

Manager Mng

## 数据结构

#### 链表类

#### 数组队列

```c

typedef _MemoryPage {
    void *page_start;
    size_t page_size;
} MemoryPage;
typedef _MemoryPageManager {
    size_t used_count;
    size_t free_count;

    MemoryPage *mps;

} MemoryPageManager;

#define MemoryPageManagerNew MemoryPageManagerAllocate

MemoryPage *MemoryPageManagerAllocate() {

}

void MemoryPageManagerFree(MemoryPage *mp) {

}
```


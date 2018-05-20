
typedef uint8_t u8;
typedef uint32_t u32;
void checkbkpt(u8 *addr, u32 size) {
    // 结果
    u32 uRet = 0;
    // 断点指令
    // u8 armBkpt[4]={0xf0,0x01,0xf0,0xe7};
    // u8 thumbBkpt[2]={0x10,0xde};
    u8 armBkpt[4]   = {0};
    armBkpt[0]      = 0xf0;
    armBkpt[1]      = 0x01;
    armBkpt[2]      = 0xf0;
    armBkpt[3]      = 0xe7;
    u8 thumbBkpt[2] = {0};
    thumbBkpt[0]    = 0x10;
    thumbBkpt[1]    = 0xde;
    // 判断模式
    int mode = (u32)addr % 2;
    if (1 == mode) {
        LOGA("checkbkpt:(thumb mode)该地址为thumb模式\n");
        u8 *start = (u8 *)((u32)addr - 1);
        u8 *end   = (u8 *)((u32)start + size);
        // 遍历对比
        while (1) {
            if (start >= end) {
                uRet = 0;
                LOGA("checkbkpt:(no find bkpt)没有发现断点.\n");
                break;
            }
            if (0 == memcmp(start, thumbBkpt, 2)) {
                uRet = 1;
                LOGA("checkbkpt:(find it)发现断点.\n");
                break;
            }
            start = start + 2;
        } //while
    }     //if
    else {
        LOGA("checkbkpt:(arm mode)该地址为arm模式\n");
        u8 *start = (u8 *)addr;
        u8 *end   = (u8 *)((u32)start + size);
        // 遍历对比
        while (1) {
            if (start >= end) {
                uRet = 0;
                LOGA("checkbkpt:(no find)没有发现断点.\n");
                break;
            }
            if (0 == memcmp(start, armBkpt, 4)) {
                uRet = 1;
                LOGA("checkbkpt:(find it)发现断点.\n");
                break;
            }
            start = start + 4;
        } //while
    }     //else
    return;
}
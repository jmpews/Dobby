
#include "PlatformInterface/Common/Platform.h"
#include "core/logging.h"
#include "core/macros.h"

std::vector<MemoryRegion> GetProcessMemoryLayout() {
  std::vector<MemoryRegion> result;

  FILE *fp = fopen("/proc/self/maps", "r");
  if (fp == nullptr)
    return result;

  while (!feof(fp)) {
    char line_buffer[1024 + 1];
    fgets(line_buffer, 1024, fp);
    // ignore the rest of characters
    if (strlen(line_buffer) == 1024 && line_buffer[1024] != '\n') {
      // Entry not describing executable data. Skip to end of line to set up
      // reading the next entry.
      int c;
      do {
        c = getc(fp);
      } while ((c != EOF) && (c != '\n'));
      if (c == EOF)
        break;
    }

    uintptr_t region_start;
    uintptr_t region_end;
    uintptr_t region_offset;
    char permissions[5] = {'\0'}; // Ensure NUL-terminated string.
    uint8_t dev_major   = 0;
    uint8_t dev_minor   = 0;
    long inode          = 0;
    int path_index      = 0;

    // Sample format from man 5 proc:
    //
    // address           perms offset  dev   inode   pathname
    // 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
    //
    // The final %n term captures the offset in the input string, which is used
    // to determine the path name. It *does not* increment the return value.
    // Refer to man 3 sscanf for details.
    if (sscanf(line_buffer,
               "%" PRIxPTR "-%" PRIxPTR " %4c "
               "%" PRIxPTR " %hhx:%hhx %ld %n",
               &region_start, &region_end, permissions, &region_offset, &dev_major, &dev_minor, &inode,
               &path_index) < 7) {
      FATAL("[!] /proc/self/maps parse failed!");
      exit(-1);
    }

    MemoryPermission permission;
    if (permissions[0] == 'r' && permissions[1] == 'w') {
      permission = MemoryPermission::kReadWrite;
    } else if (permissions[0] == 'r' && permissions[2] == 'x') {
      permission = MemoryPermission::kReadExecute;
    } else if (permissions[0] == 'r' && permissions[1] == 'w' && permissions[2] == 'x') {
      permission = MemoryPermission::kReadWriteExecute;
    } else {
      permission = MemoryPermission::kNoAccess;
    }

    result.push_back(MemoryRegion(region_start, region_end, permission));
  }
  return result;
}
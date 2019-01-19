
#include "PlatformInterface/platform.h"
#include "core/logging.h"
#include "core/macros.h"

namespace zz {

std::vector<OSMemory::SharedLibraryAddress> OSMemory::GetSharedLibraryAddresses() {
  std::vector<SharedLibraryAddress> result;
  // This function assumes that the layout of the file is as follows:
  // hex_start_addr-hex_end_addr rwxp <unused data> [binary_file_name]
  // If we encounter an unexpected situation we abort scanning further entries.
  FILE *fp = fopen("/proc/self/maps", "r");
  if (fp == nullptr)
    return result;

  // Allocate enough room to be able to store a full file name.
  const int kLibNameLen = FILENAME_MAX + 1;
  char *lib_name        = reinterpret_cast<char *>(malloc(kLibNameLen));

  // This loop will terminate once the scanning hits an EOF.
  while (true) {
    uintptr_t start, end, offset;
    char attr_r, attr_w, attr_x, attr_p;
    // Parse the addresses and permission bits at the beginning of the line.
    if (fscanf(fp, "%" PRIxPTR "-%" PRIxPTR, &start, &end) != 2)
      break;
    if (fscanf(fp, " %c%c%c%c", &attr_r, &attr_w, &attr_x, &attr_p) != 4)
      break;
    if (fscanf(fp, "%" PRIxPTR, &offset) != 1)
      break;

    // Adjust {start} based on {offset}.
    start -= offset;

    int c;
    if (attr_r == 'r' && attr_w != 'w' && attr_x == 'x') {
      // Found a read-only executable entry. Skip characters until we reach
      // the beginning of the filename or the end of the line.
      do {
        c = getc(fp);
      } while ((c != EOF) && (c != '\n') && (c != '/') && (c != '['));
      if (c == EOF)
        break; // EOF: Was unexpected, just exit.

      // Process the filename if found.
      if ((c == '/') || (c == '[')) {
        // Push the '/' or '[' back into the stream to be read below.
        ungetc(c, fp);

        // Read to the end of the line. Exit if the read fails.
        if (fgets(lib_name, kLibNameLen, fp) == nullptr)
          break;

        // Drop the newline character read by fgets. We do not need to check
        // for a zero-length string because we know that we at least read the
        // '/' or '[' character.
        lib_name[strlen(lib_name) - 1] = '\0';
      } else {
        // No library name found, just record the raw address range.
        snprintf(lib_name, kLibNameLen, "%08" PRIxPTR "-%08" PRIxPTR, start, end);
      }
      result.push_back(SharedLibraryAddress(lib_name, start, end));
    } else {
      // Entry not describing executable data. Skip to end of line to set up
      // reading the next entry.
      do {
        c = getc(fp);
      } while ((c != EOF) && (c != '\n'));
      if (c == EOF)
        break;
    }
  }
  free(lib_name);
  fclose(fp);
  return result;
}

std::vector<OSMemory::MemoryRegion> OSMemory::GetMemoryLayout() {
  std::vector<OSMemory::MemoryRegion> result;

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

    result.push_back(OSMemory::MemoryRegion(region_start, region_end, permission));
  }
  return result;
}

} // namespace zz


#include "vm_core/platform/platform.h"
#include "vm_core/platform/platform-posix.h"

namespace zz {

  std::vector <OS::SharedLibraryAddress> OS::GetSharedLibraryAddresses() {
    std::vector <SharedLibraryAddress> result;
    // This function assumes that the layout of the file is as follows:
    // hex_start_addr-hex_end_addr rwxp <unused data> [binary_file_name]
    // If we encounter an unexpected situation we abort scanning further entries.
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr)
      return result;

    // Allocate enough room to be able to store a full file name.
    const int kLibNameLen = FILENAME_MAX + 1;
    char *lib_name = reinterpret_cast<char *>(malloc(kLibNameLen));

    // This loop will terminate once the scanning hits an EOF.
    while (true) {
      uintptr_t start, end, offset;
      char attr_r, attr_w, attr_x, attr_p;
      // Parse the addresses and permission bits at the beginning of the line.
      if (fscanf(fp,
                 "%lx"
                     "-%lx",
                 &start, &end) != 2)
        break;
      if (fscanf(fp, " %c%c%c%c", &attr_r, &attr_w, &attr_x, &attr_p) != 4)
        break;
      if (fscanf(fp, "%lx", &offset) != 1)
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
          snprintf(lib_name, kLibNameLen,
                   "%08lx"
                       "-%08lx",
                   start, end);
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

  std::vector <OS::MemoryRegion> OS::GetMemoryLayout() {
  }

}
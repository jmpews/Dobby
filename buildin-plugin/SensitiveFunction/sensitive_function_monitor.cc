#include "dobby.h"

namespace monitor {

void monitor_crypto() {
  const char *crypto_sensitive_regx_list[] = {
      // xxtea crypto algorithm
      ".*xxtea_decrypt.*",
      ".*xxtea_encrypt.*",

      // lua script load
      ".*luaL_loadbuffer.*",
  };
}

} // namespace monitor
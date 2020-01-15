#include "dobby.h"
#include "dobby_find_symbol.h"

namespace monitor {

const char *crypto_regex_list[] = {
    // xxtea crypto algorithm
    ".*xxtea_decrypt.*", ".*xxtea_encrypt.*",
};

const char *lua_regex_list[] = {
    // lua script load
    ".*luaL_loadbuffer.*",
};

const char *unity3d_regex_list[] = {
    "mono_image_open_from_data_with_name",
};

void monitor_crypto() {
}

} // namespace monitor
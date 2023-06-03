#pragma once

#include "logging/logging.h"
#include <string.h>

inline void debug_hex_log_buffer(const uint8_t *buffer, uint32_t buffer_size) {
  char print_buf[1024] = {0};
  for (int i = 0; i < buffer_size && i < sizeof(print_buf); i++) {
    snprintf(print_buf + strlen(print_buf), sizeof(print_buf) - strlen(print_buf), "%02x ", *((uint8_t *)buffer + i));
  }
  print_buf[sizeof(print_buf) - 1] = 0;
  DEBUG_LOG("%s", print_buf);
};